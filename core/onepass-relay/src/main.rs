//! `onepass-relay`: the native messaging host Chrome and Firefox launch
//! (`me.somalabs.onepass`), shipped in `OnePass.app/Contents/Helpers`.
//!
//! It finds the app's socket in the App Group container of its own team,
//! checks that the listener is the OnePass app of that team, sends the
//! extension id the browser gave, then copies frames both ways without
//! reading them. Any failure exits without a word: the extension sees the
//! port close and says the app is not reachable. It never touches the
//! vault, never keeps state, and never writes anything.

use std::process::ExitCode;

use onepass_relay::Preamble;
use onepass_relay::preamble::extension_from_args;
use onepass_relay::rendezvous::{
    RELAY_SUFFIX, own_identity, peer_identity, socket_path, user_home,
};
use onepass_relay::server::{connect, pump};

fn run() -> Option<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let extension = extension_from_args(&args)?;
    // Signed `<app>.relay`: the app it may talk to is `<app>`.
    let (team, me) = own_identity()?;
    let app = me.strip_suffix(RELAY_SUFFIX)?;
    let path = socket_path(&user_home()?, &team)?;
    let stream = connect(
        &path,
        &team,
        app,
        &peer_identity,
        &Preamble::new(Some(extension)),
    )
    .ok()?;
    pump(std::io::stdin(), std::io::stdout().lock(), stream).ok()
}

fn main() -> ExitCode {
    match run() {
        Some(()) => ExitCode::SUCCESS,
        None => ExitCode::FAILURE,
    }
}
