//! The test mailbox server on its own (debug builds, `--features
//! test-mailbox`): the sync end-to-end test runs it, and so does a
//! cross-device test with Android (`adb reverse tcp:<port> tcp:<port>`, then
//! the base URL below and the test CA as "Mon serveur").
//!
//!   test-mailbox [--port <port>] [--ca-out <file>]
//!
//! The port defaults to ONEPASS_TEST_MAILBOX_PORT, else 47800. The first
//! line on stdout is the base URL; the test CA is written to `--ca-out`
//! (default: `test-mailbox-ca.pem` next to the binary). Runs until killed.

#[path = "../testmailbox.rs"]
mod testmailbox;

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut port: u16 = std::env::var("ONEPASS_TEST_MAILBOX_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(47800);
    let mut ca_out: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => {
                port = args
                    .next()
                    .and_then(|p| p.parse().ok())
                    .expect("--port <port>")
            }
            "--ca-out" => ca_out = args.next().map(PathBuf::from),
            other => panic!("unknown argument {other}"),
        }
    }
    let ca_out = ca_out.unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.join("test-mailbox-ca.pem")))
            .unwrap_or_else(|| "test-mailbox-ca.pem".into())
    });
    std::fs::write(&ca_out, testmailbox::CA_PEM).expect("write the test CA");
    let base = testmailbox::start(port).expect("start the test mailbox");
    println!("{base}");
    println!("CA: {}", ca_out.display());
    use std::io::Write;
    let _ = std::io::stdout().flush();
    loop {
        std::thread::park();
    }
}
