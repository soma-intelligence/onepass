//! Running system commands (`networksetup`, `security`, `curl`) behind a
//! trait, so the tests can answer in their place. Callers name programs by
//! absolute path ([`NETWORKSETUP`], [`SECURITY`], `/usr/bin/curl`), so
//! `PATH` cannot substitute another program.
//!
//! In a debug build, `ONEPASS_DEV_FAKE_EXEC_DIR=<dir>` replaces every run
//! of `program args...` by the content of
//! `<dir>/<program base name>-<args joined by _>.out`, each character
//! outside `[A-Za-z0-9._-]` replaced by `_`. A missing file is a failed
//! command.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::session::CliError;

/// Largest standard output read from a command.
const MAX_OUTPUT: u64 = 16 * 1024 * 1024;

const FAKE_ENV: &str = "ONEPASS_DEV_FAKE_EXEC_DIR";

/// macOS network configuration tool.
pub const NETWORKSETUP: &str = "/usr/sbin/networksetup";
/// macOS keychain tool.
pub const SECURITY: &str = "/usr/bin/security";

/// Last component of `program` (`curl` for `/usr/bin/curl`), for messages
/// and fake answers.
fn base_name(program: &str) -> &str {
    Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program)
}

pub trait CommandRunner {
    /// Standard output of `program args...`. A non-zero exit is an error
    /// that never carries the command's stderr.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Vec<u8>, CliError>;
}

/// Runs the real program, stdin and stderr closed, stdout capped at 16 MiB.
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&mut self, path: &str, args: &[&str]) -> Result<Vec<u8>, CliError> {
        let program = base_name(path);
        let mut child = Command::new(path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| CliError::usage(format!("cannot run {program}")))?;
        let mut out = Vec::new();
        let read = match child.stdout.take() {
            Some(stdout) => stdout.take(MAX_OUTPUT + 1).read_to_end(&mut out),
            None => Ok(0),
        };
        if read.is_err() || out.len() as u64 > MAX_OUTPUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CliError::usage(format!(
                "{program}: output unreadable or too large"
            )));
        }
        let status = child
            .wait()
            .map_err(|_| CliError::usage(format!("cannot run {program}")))?;
        if !status.success() {
            return Err(CliError::usage(format!("{program} failed")));
        }
        Ok(out)
    }
}

/// Answers from files of a directory (tests): see the module doc.
pub struct FakeRunner {
    dir: PathBuf,
}

impl CommandRunner for FakeRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Vec<u8>, CliError> {
        let program = base_name(program);
        std::fs::read(self.dir.join(fake_file_name(program, args)))
            .map_err(|_| CliError::usage(format!("{program} failed")))
    }
}

/// `<program>-<args joined by _>.out`, every character outside
/// `[A-Za-z0-9._-]` replaced by `_`.
pub fn fake_file_name(program: &str, args: &[&str]) -> String {
    let raw = format!("{program}-{}", args.join("_"));
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    name.push_str(".out");
    name
}

/// The runner to use: the fake one when `ONEPASS_DEV_FAKE_EXEC_DIR` is set
/// (refused in a release build), else the system.
pub fn runner() -> Result<Box<dyn CommandRunner>, CliError> {
    match std::env::var_os(FAKE_ENV) {
        Some(dir) => {
            if !cfg!(debug_assertions) {
                return Err(CliError::usage(
                    "ONEPASS_DEV_FAKE_EXEC_DIR is refused in a release build",
                ));
            }
            Ok(Box::new(FakeRunner {
                dir: PathBuf::from(dir),
            }))
        }
        None => Ok(Box::new(SystemRunner)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_names_are_sanitized() {
        assert_eq!(
            fake_file_name("networksetup", &["-listallhardwareports"]),
            "networksetup--listallhardwareports.out"
        );
        assert_eq!(
            fake_file_name(
                "security",
                &[
                    "find-generic-password",
                    "-D",
                    "AirPort network password",
                    "-a",
                    "Cafe/../é",
                    "-w"
                ]
            ),
            "security-find-generic-password_-D_AirPort_network_password_-a_Cafe_..___-w.out"
        );
    }

    #[test]
    fn fake_runner_maps_absolute_paths_by_base_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("networksetup--listallhardwareports.out"),
            b"ports",
        )
        .unwrap();
        let mut r = FakeRunner {
            dir: dir.path().to_path_buf(),
        };
        assert_eq!(
            r.run(NETWORKSETUP, &["-listallhardwareports"]).unwrap(),
            b"ports"
        );
        let e = r.run(SECURITY, &["x"]).unwrap_err();
        assert_eq!(e.msg, "security failed");
    }

    #[test]
    fn system_runner_reports_failure_without_stderr() {
        let mut r = SystemRunner;
        assert_eq!(r.run("sh", &["-c", "printf ok"]).unwrap(), b"ok");
        let e = r
            .run("sh", &["-c", "echo secret-detail >&2; exit 3"])
            .unwrap_err();
        assert_eq!(e.code, 1);
        assert!(!e.msg.contains("secret-detail"));
    }
}
