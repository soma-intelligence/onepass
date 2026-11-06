//! Running system programs behind a trait, so tests can answer instead.
//!
//! Arguments are passed verbatim: on Windows each one is appended to the
//! command line as is (`raw_arg`), because `netsh` wants `name="x y"`
//! with its own quotes, which the standard quoting would escape. Callers
//! never put a secret in an argument.

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::{Result, WifiError};

/// Largest standard output read from a program.
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;

/// Exit status and standard output of a program.
pub struct Output {
    pub ok: bool,
    pub stdout: Vec<u8>,
}

pub trait Exec {
    /// Run `program args...` with stdin and stderr closed. Spawn failures
    /// are errors; a non-zero exit is `ok: false`.
    fn run(&mut self, program: &Path, args: &[String]) -> Result<Output>;
}

/// Runs the real program.
pub struct SystemExec;

fn name_of(program: &Path) -> String {
    program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl Exec for SystemExec {
    fn run(&mut self, program: &Path, args: &[String]) -> Result<Output> {
        let name = name_of(program);
        let mut cmd = Command::new(program);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: no console flashes under the login agent.
            cmd.creation_flags(0x0800_0000);
            for a in args {
                cmd.raw_arg(a);
            }
        }
        #[cfg(not(windows))]
        cmd.args(args);
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| WifiError::new(format!("cannot run {name}")))?;
        let mut stdout = Vec::new();
        let read = match child.stdout.take() {
            Some(s) => s.take(MAX_OUTPUT + 1).read_to_end(&mut stdout),
            None => Ok(0),
        };
        if read.is_err() || stdout.len() as u64 > MAX_OUTPUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WifiError::new(format!("{name}: output unreadable")));
        }
        let status = child
            .wait()
            .map_err(|_| WifiError::new(format!("cannot run {name}")))?;
        Ok(Output {
            ok: status.success(),
            stdout,
        })
    }
}
