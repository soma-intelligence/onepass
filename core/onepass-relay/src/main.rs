//! `onepass-relay`: the native messaging host Chrome and Firefox launch
//! (`me.somalabs.onepass`), shipped in `OnePass.app/Contents/Helpers`.
//!
//! It finds the app's socket in the App Group container of its own team,
//! checks that the listener is the OnePass app of that team, sends the
//! extension id the browser gave and the verified code identity of the
//! process that launched it (the browser), then copies frames both ways
//! without reading them. Any failure exits without a word: the extension sees the
//! port close and says the app is not reachable. It never touches the
//! vault, never keeps state, and never writes anything.
//!
//! One exception to "without reading": a connection whose first frame is
//! exactly `open_app::REQUEST` asks the app to come forward on its lock
//! screen (see `open_app`), and ends.

use std::io::{Cursor, Read};
use std::process::{Command, ExitCode, Stdio};

use onepass_bridge::framing::{read_frame, write_frame};
use onepass_relay::open_app;

use onepass_peer::{CodeIdentity, identify_pid, parent_pid};
use onepass_relay::Preamble;
use onepass_relay::preamble::extension_from_args;
use onepass_relay::rendezvous::{
    RELAY_SUFFIX, own_identity, peer_identity, socket_path, user_home,
};
use onepass_relay::server::{connect, pump};

/// The client id of the process that launched this relay, when it is signed
/// by a team (spec 2026-11-02-browser-auto-pairing, ruling A1). The parent
/// pid is read again after the identification: if it changed, the parent
/// exited and its pid may name another process by now, so nothing is
/// vouched. A browser keeps the relay's pipes open, hence stays alive, for
/// as long as it uses it.
fn parent_launcher() -> Option<String> {
    let pid = parent_pid();
    if pid <= 1 {
        return None;
    }
    let id = identify_pid(pid).ok()?.code;
    if parent_pid() != pid {
        return None;
    }
    matches!(id, CodeIdentity::Team { .. }).then(|| id.client_id())
}

fn run() -> Option<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let extension = extension_from_args(&args)?;
    // Signed `<app>.relay`: the app it may talk to is `<app>`.
    let (team, me) = own_identity()?;
    let app = me.strip_suffix(RELAY_SUFFIX)?;
    let mut stdin = std::io::stdin();
    let first = read_frame(&mut stdin).ok()??;
    if open_app::is_request(&first) {
        let (program, args) = open_app::command(app);
        let opened = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?
            .success();
        return opened.then(|| write_frame(&mut std::io::stdout().lock(), open_app::REPLY).ok())?;
    }
    let path = socket_path(&user_home()?, &team)?;
    let stream = connect(
        &path,
        &team,
        app,
        &peer_identity,
        &Preamble::with_launcher(extension, parent_launcher()),
    )
    .ok()?;
    // The frame read above goes first, unchanged.
    let mut head = Vec::new();
    write_frame(&mut head, &first).ok()?;
    pump(
        Cursor::new(head).chain(stdin),
        std::io::stdout().lock(),
        stream,
    )
    .ok()
}

fn main() -> ExitCode {
    match run() {
        Some(()) => ExitCode::SUCCESS,
        None => ExitCode::FAILURE,
    }
}
