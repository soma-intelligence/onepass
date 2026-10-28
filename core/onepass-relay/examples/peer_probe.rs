//! Probe, never shipped: does the code-signature check of `onepass-peer`
//! work inside the App Sandbox, both ways? Sign two copies with the team's
//! identity, App Sandbox and the App Group (and an embedded Info.plist), then:
//!
//! `peer_probe serve <socket>` (prints the client's identity, answers `ok`)
//! `peer_probe connect <socket>` (prints the listener's identity)

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

use onepass_relay::rendezvous::{own_team, peer_identity};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(mode), Some(path)) = (args.first(), args.get(1)) else {
        eprintln!("usage: peer_probe serve|connect <socket>");
        std::process::exit(64);
    };
    println!("own team: {:?}", own_team());
    if mode == "serve" {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path).expect("bind");
        println!("listening");
        let (mut s, _) = l.accept().expect("accept");
        println!("client: {:?}", peer_identity(&s));
        let _ = s.write_all(b"ok");
        let _ = std::fs::remove_file(path);
    } else {
        let mut s = UnixStream::connect(path).expect("connect");
        println!("listener: {:?}", peer_identity(&s));
        let mut b = [0u8; 2];
        let _ = s.read_exact(&mut b);
        println!("read {}", String::from_utf8_lossy(&b));
    }
}
