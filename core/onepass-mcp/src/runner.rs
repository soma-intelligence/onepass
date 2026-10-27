//! The command runner of `run_with_secrets` (spec section 4.3).
//!
//! `argv` runs directly, never through an implicit shell. The child gets
//! the server's environment minus every `ONEPASS_*` variable, plus the
//! requested variables; secret files live in a private temporary
//! directory (`0700`, files `0600`) removed when the run ends. There is no
//! standard input. stdout and stderr are read by two threads that keep at
//! most [`MAX_OUTPUT`] bytes each (the rest is read and dropped, so the
//! child never blocks on a full pipe). The child leads its own process
//! group: past the timeout the whole group is killed (`SIGKILL`), and so
//! is whatever the command left running once it exits, so no background
//! job outlives the run with the injected secrets.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Most bytes kept per output stream.
pub const MAX_OUTPUT: usize = 64 * 1024;

/// How often the child is polled.
const POLL: Duration = Duration::from_millis(20);

/// How long to wait for the output readers once the child is gone, when a
/// grandchild may still hold the pipes open.
const READER_GRACE: Duration = Duration::from_millis(500);

/// What to run. `env` and `files` carry secret values: the names come from
/// the agent (validated by the caller), the values from the vault.
pub struct RunRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, Zeroizing<String>)>,
    pub files: Vec<(String, Zeroizing<String>)>,
    pub cwd: Option<PathBuf>,
    pub timeout: Duration,
}

/// What a run produced. Output is converted to UTF-8 with replacement and
/// may contain secrets until masked: it is zeroized on drop and its
/// `Debug` shows lengths only.
pub struct RunOutput {
    /// Exit code, `None` when killed by a signal.
    pub code: Option<i32>,
    pub stdout: Zeroizing<String>,
    pub stderr: Zeroizing<String>,
    /// The child was killed at the timeout.
    pub timed_out: bool,
    /// One of the streams went over [`MAX_OUTPUT`].
    pub truncated: bool,
}

impl fmt::Debug for RunOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunOutput")
            .field("code", &self.code)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .field("timed_out", &self.timed_out)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// One stream as read so far: the bytes kept and whether some were dropped.
type Captured = Arc<Mutex<(Zeroizing<Vec<u8>>, bool)>>;

/// Sends `SIGKILL` to the process group `pgid` (the child's pid, as it was
/// spawned with `process_group(0)`). Errors are ignored: the group may be
/// gone already.
fn kill_group(pgid: u32) {
    let kill = if std::path::Path::new("/bin/kill").exists() {
        "/bin/kill"
    } else {
        "kill"
    };
    let _ = Command::new(kill)
        .args(["-s", "KILL", "--", &format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Runs `req` and waits for it, at most `req.timeout`.
pub fn run(req: &RunRequest) -> io::Result<RunOutput> {
    run_with_parent_env(req, std::env::vars_os().collect())
}

/// [`run`] with the parent environment given explicitly (the child starts
/// from it, without its `ONEPASS_*` variables).
fn run_with_parent_env(
    req: &RunRequest,
    parent: Vec<(OsString, OsString)>,
) -> io::Result<RunOutput> {
    let (program, args) = req
        .argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .process_group(0)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in parent {
        if !k.to_string_lossy().starts_with("ONEPASS_") {
            cmd.env(k, v);
        }
    }
    for (k, v) in &req.env {
        cmd.env(k, v.as_str());
    }
    // Dropped (and removed) when this function returns, whatever happens.
    let dir = if req.files.is_empty() {
        None
    } else {
        Some(secret_dir(&req.files)?)
    };
    if let Some(dir) = &dir {
        for (name, _) in &req.files {
            cmd.env(name, dir.path().join(name));
        }
    }
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }

    let start = Instant::now();
    let mut child = cmd.spawn()?;
    let pgid = child.id();
    let (done_tx, done_rx) = mpsc::channel();
    let stdout = capture(child.stdout.take(), done_tx.clone());
    let stderr = capture(child.stderr.take(), done_tx);

    let mut timed_out = false;
    let status = loop {
        let polled = match child.try_wait() {
            Ok(p) => p,
            Err(e) => {
                kill_group(pgid);
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        if let Some(status) = polled {
            break status;
        }
        if start.elapsed() >= req.timeout {
            timed_out = true;
            kill_group(pgid);
            // Already exited between the two calls is fine.
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(POLL);
    };

    // Readers end at end of file. A background job that kept the pipes
    // open can delay that: wait a short grace, then kill the group (which
    // closes the pipes) and take what was read.
    let deadline = Instant::now() + READER_GRACE;
    let mut finished = 0;
    while finished < 2 {
        let left = deadline.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
        finished += 1;
    }
    // Whatever the command left behind goes too, pipes held or not.
    kill_group(pgid);
    let (out, out_cut) = take(&stdout);
    let (err, err_cut) = take(&stderr);
    drop(dir);
    Ok(RunOutput {
        code: status.code(),
        stdout: Zeroizing::new(String::from_utf8_lossy(&out).into_owned()),
        stderr: Zeroizing::new(String::from_utf8_lossy(&err).into_owned()),
        timed_out,
        truncated: out_cut || err_cut,
    })
}

/// A `0700` temporary directory holding one `0600` file per entry.
fn secret_dir(files: &[(String, Zeroizing<String>)]) -> io::Result<tempfile::TempDir> {
    let dir = tempfile::Builder::new().prefix("onepass-run-").tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    for (name, value) in files {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad file name"));
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join(name))?;
        f.write_all(value.as_bytes())?;
    }
    Ok(dir)
}

/// Reads `pipe` to its end on a thread, keeping at most [`MAX_OUTPUT`]
/// bytes; signals `done` at the end.
fn capture<R: Read + Send + 'static>(pipe: Option<R>, done: mpsc::Sender<()>) -> Captured {
    // Allocated once at full size, so no reallocation leaves a copy behind.
    let captured: Captured = Arc::new(Mutex::new((
        Zeroizing::new(Vec::with_capacity(MAX_OUTPUT)),
        false,
    )));
    let shared = captured.clone();
    thread::spawn(move || {
        if let Some(mut pipe) = pipe {
            let mut buf = Zeroizing::new([0u8; 8192]);
            loop {
                match pipe.read(&mut buf[..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut c = shared.lock().unwrap_or_else(|e| e.into_inner());
                        let room = MAX_OUTPUT - c.0.len();
                        if n > room {
                            c.1 = true;
                        }
                        let keep = n.min(room);
                        c.0.extend_from_slice(&buf[..keep]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }
        let _ = done.send(());
    });
    captured
}

fn take(c: &Captured) -> (Zeroizing<Vec<u8>>, bool) {
    let mut c = c.lock().unwrap_or_else(|e| e.into_inner());
    (std::mem::take(&mut c.0), c.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(argv: &[&str]) -> RunRequest {
        RunRequest {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            env: Vec::new(),
            files: Vec::new(),
            cwd: None,
            timeout: Duration::from_secs(20),
        }
    }

    #[test]
    fn run_captures_exit_code_and_output() {
        let out = run(&req(&["/bin/sh", "-c", "echo hi; echo err >&2; exit 3"])).unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(*out.stdout, "hi\n");
        assert_eq!(*out.stderr, "err\n");
        assert!(!out.timed_out && !out.truncated);
    }

    #[test]
    fn run_times_out() {
        let mut r = req(&["sleep", "5"]);
        r.timeout = Duration::from_secs(1);
        let start = Instant::now();
        let out = run(&r).unwrap();
        assert!(out.timed_out);
        assert_eq!(out.code, None);
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    /// Whether the process group `pgid` still has a member.
    fn group_alive(pgid: &str) -> bool {
        Command::new("/bin/kill")
            .args(["-s", "0", "--", &format!("-{pgid}")])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    #[test]
    fn run_kills_the_whole_group_at_the_timeout() {
        let mut r = req(&["/bin/sh", "-c", "echo $$; sleep 30 & sleep 30"]);
        r.timeout = Duration::from_secs(1);
        let start = Instant::now();
        let out = run(&r).unwrap();
        assert!(out.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        let pgid = out.stdout.trim();
        assert!(!pgid.is_empty());
        assert!(!group_alive(pgid), "group {pgid} survived");
    }

    #[test]
    fn run_ends_background_jobs_after_a_short_grace() {
        let r = req(&["/bin/sh", "-c", "echo $$; sleep 30 & echo started"]);
        let start = Instant::now();
        let out = run(&r).unwrap();
        assert_eq!(out.code, Some(0));
        let mut lines = out.stdout.lines();
        let pgid = lines.next().unwrap().to_owned();
        assert_eq!(lines.next(), Some("started"));
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(!group_alive(&pgid), "group {pgid} survived");
    }

    #[test]
    fn run_output_debug_shows_lengths_only() {
        let out = run(&req(&["/bin/echo", "very-secret-output"])).unwrap();
        let debug = format!("{out:?}");
        assert!(!debug.contains("very-secret"), "{debug}");
        assert!(debug.contains("stdout_len: 19"), "{debug}");
    }

    #[test]
    fn run_truncates_large_output() {
        let out = run(&req(&["head", "-c", "200000", "/dev/zero"])).unwrap();
        assert_eq!(out.code, Some(0));
        assert!(out.truncated);
        assert_eq!(out.stdout.len(), MAX_OUTPUT);
    }

    #[test]
    fn run_files_are_0600_and_removed() {
        let mut r = req(&[
            "/bin/sh",
            "-c",
            r#"ls -ld "$(dirname "$KEY")" | cut -c1-10; ls -l "$KEY" | cut -c1-10; cat "$KEY"; echo; echo "$KEY""#,
        ]);
        r.files = vec![("KEY".into(), Zeroizing::new("file-secret".into()))];
        let out = run(&r).unwrap();
        let lines: Vec<&str> = out.stdout.lines().collect();
        assert_eq!(lines[0], "drwx------", "{}", out.stdout.as_str());
        assert_eq!(lines[1], "-rw-------", "{}", out.stdout.as_str());
        assert_eq!(lines[2], "file-secret");
        let path = std::path::Path::new(lines[3]);
        assert!(path.ends_with("KEY"));
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn run_strips_onepass_env() {
        let mut r = req(&["/bin/sh", "-c", "env"]);
        r.env = vec![("ADDED".into(), Zeroizing::new("added-value".into()))];
        let parent = vec![
            (
                OsString::from("ONEPASS_PASSWORD"),
                OsString::from("leak-me"),
            ),
            (OsString::from("ONEPASS_DEV_X"), OsString::from("1")),
            (OsString::from("KEEP_ME"), OsString::from("kept")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ];
        let out = run_with_parent_env(&r, parent).unwrap();
        assert!(!out.stdout.contains("ONEPASS_"), "{}", out.stdout.as_str());
        assert!(!out.stdout.contains("leak-me"));
        assert!(out.stdout.contains("KEEP_ME=kept"));
        assert!(out.stdout.contains("ADDED=added-value"));
    }

    #[test]
    fn run_has_no_stdin_and_honours_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = req(&["/bin/sh", "-c", "cat; pwd"]);
        r.cwd = Some(dir.path().to_path_buf());
        let out = run(&r).unwrap();
        let canon = dir.path().canonicalize().unwrap();
        assert_eq!(out.stdout.trim_end(), canon.to_str().unwrap());
    }

    #[test]
    fn run_reports_missing_program_and_empty_command() {
        assert!(run(&req(&["/nonexistent/onepass-test-binary"])).is_err());
        assert_eq!(
            run(&req(&[])).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
