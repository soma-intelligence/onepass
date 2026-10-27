//! Where the secret tools touch the user's machine (spec sections 4.3 of
//! milestone 7 and 4.2 of the app design).
//!
//! `run_with_secrets` runs a command, `fill_template` reads a template and
//! checks then writes its output. These four side effects go through a
//! [`Workspace`]: [`LocalWorkspace`] does them in this process (the CLI),
//! the Mac app hands them to its relay, outside the sandbox. Everything
//! else (policy, approval, audit, masking of the output) stays in the
//! tools, whatever the workspace.
//!
//! Refusals carry a message free of paths' content and values, returned to
//! the agent as it is. The checks of [`LocalWorkspace`] are the contract:
//! another workspace must apply the same ones, best by delegating to it.

use crate::runner::{self, RunOutput, RunRequest};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Largest template `fill_template` reads.
pub const MAX_TEMPLATE: u64 = 1024 * 1024;

/// A side effect refused or failed, with the exact message the agent gets.
/// The message never holds a secret value or file content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRefusal(String);

impl WorkspaceRefusal {
    /// A refusal with `message` (free of secret values and file content).
    pub fn new(message: impl Into<String>) -> Self {
        WorkspaceRefusal(message.into())
    }

    /// The message returned to the agent.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkspaceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WorkspaceRefusal {}

/// The side effects of the secret tools. `forbidden` is the data
/// directory, never read nor written.
pub trait Workspace {
    /// Runs `req` and returns its raw output (masked later by the tool).
    fn run(&self, req: &RunRequest) -> Result<RunOutput, WorkspaceRefusal>;

    /// The template at `path`: a regular UTF-8 file of at most
    /// [`MAX_TEMPLATE`] bytes, outside `forbidden`.
    fn read_template(
        &self,
        path: &Path,
        forbidden: Option<&Path>,
    ) -> Result<Zeroizing<String>, WorkspaceRefusal>;

    /// Checks that `path` may receive the output: an existing directory
    /// outside `forbidden`, no symbolic link, no existing file unless
    /// `overwrite`.
    fn check_output(
        &self,
        path: &Path,
        overwrite: bool,
        forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal>;

    /// Checks `path` again as [`Workspace::check_output`] does, then
    /// writes `content` to it with mode `0600`.
    fn write_output(
        &self,
        path: &Path,
        content: &str,
        overwrite: bool,
        forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal>;
}

/// The workspace of this process: the command runs here
/// ([`runner::run`]), files are read and written here.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalWorkspace;

impl Workspace for LocalWorkspace {
    fn run(&self, req: &RunRequest) -> Result<RunOutput, WorkspaceRefusal> {
        runner::run(req).map_err(|e| io_refusal("command could not be started", &e))
    }

    fn read_template(
        &self,
        path: &Path,
        forbidden: Option<&Path>,
    ) -> Result<Zeroizing<String>, WorkspaceRefusal> {
        read_template(path, forbidden)
    }

    fn check_output(
        &self,
        path: &Path,
        overwrite: bool,
        forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal> {
        output_target(path, overwrite, forbidden).map(drop)
    }

    fn write_output(
        &self,
        path: &Path,
        content: &str,
        overwrite: bool,
        forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal> {
        let target = output_target(path, overwrite, forbidden)?;
        write_private(&target, content.as_bytes(), overwrite)
    }
}

fn io_refusal(what: &str, e: &io::Error) -> WorkspaceRefusal {
    WorkspaceRefusal(format!("{what}: {}", e.kind()))
}

fn invalid(m: &str) -> WorkspaceRefusal {
    WorkspaceRefusal(m.to_owned())
}

/// Where the output may go: an existing directory outside the data
/// directory, no symbolic link, no existing file unless `overwrite`.
/// Returns the resolved path.
fn output_target(
    out: &Path,
    overwrite: bool,
    forbidden: Option<&Path>,
) -> Result<PathBuf, WorkspaceRefusal> {
    let (Some(parent), Some(name)) = (out.parent(), out.file_name()) else {
        return Err(invalid("output path must name a file"));
    };
    let parent = parent
        .canonicalize()
        .map_err(|e| io_refusal("output directory is not usable", &e))?;
    let target = parent.join(name);
    if let Some(dir) = forbidden {
        let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        if target.starts_with(&dir) {
            return Err(invalid("output path is inside the data directory"));
        }
    }
    match fs::symlink_metadata(&target) {
        Ok(m) if m.file_type().is_symlink() => Err(invalid("output path is a symbolic link")),
        Ok(_) if !overwrite => Err(invalid("output file exists, set overwrite to replace it")),
        Ok(m) if !m.is_file() => Err(invalid("output path is not a regular file")),
        // A hard link would carry the secrets to another name.
        Ok(m) if m.nlink() > 1 => Err(invalid("output file has other hard links")),
        Ok(_) => Ok(target),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(target),
        Err(e) => Err(io_refusal("output path is not usable", &e)),
    }
}

/// The template at `path`: a regular file of at most [`MAX_TEMPLATE`]
/// bytes, in UTF-8, outside `forbidden` (the data directory), which
/// answers exactly like a missing file.
fn read_template(
    path: &Path,
    forbidden: Option<&Path>,
) -> Result<Zeroizing<String>, WorkspaceRefusal> {
    let unreadable = |e: &io::Error| io_refusal("template could not be read", e);
    let real = path.canonicalize().map_err(|e| unreadable(&e))?;
    if let Some(dir) = forbidden {
        let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        if real.starts_with(&dir) {
            return Err(unreadable(&io::Error::from(io::ErrorKind::NotFound)));
        }
    }
    let file = fs::File::open(&real).map_err(|e| unreadable(&e))?;
    let meta = file.metadata().map_err(|e| unreadable(&e))?;
    if !meta.is_file() {
        return Err(invalid("template is not a regular file"));
    }
    if meta.len() > MAX_TEMPLATE {
        return Err(invalid("template is too large"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_TEMPLATE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unreadable(&e))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("template is not valid UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Writes `data` to `path` with mode `0600`: a new file, or the existing
/// regular file when `overwrite`.
fn write_private(path: &Path, data: &[u8], overwrite: bool) -> Result<(), WorkspaceRefusal> {
    let mut opts = OpenOptions::new();
    opts.write(true).mode(0o600);
    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| io_refusal("output could not be written", &e))?;
    f.set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| f.write_all(data))
        .map_err(|e| io_refusal("output could not be written", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_checks_refuse_with_the_tool_messages() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        let w = LocalWorkspace;
        let inside = data.join("out.env");
        assert_eq!(
            w.check_output(&inside, false, Some(&data))
                .unwrap_err()
                .message(),
            "output path is inside the data directory"
        );
        let out = dir.path().join("out.env");
        w.write_output(&out, "A=1\n", false, Some(&data)).unwrap();
        let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            w.write_output(&out, "A=2\n", false, None)
                .unwrap_err()
                .message(),
            "output file exists, set overwrite to replace it"
        );
        w.write_output(&out, "A=2\n", true, None).unwrap();
        assert_eq!(fs::read_to_string(&out).unwrap(), "A=2\n");

        let t = data.join("t.tpl");
        fs::write(&t, "x").unwrap();
        assert_eq!(
            w.read_template(&t, Some(&data)).unwrap_err().message(),
            "template could not be read: entity not found"
        );
        assert_eq!(*w.read_template(&t, None).unwrap(), "x");
    }

    #[test]
    fn local_run_refuses_a_missing_program_by_kind_only() {
        let req = RunRequest {
            argv: vec!["/nonexistent/onepass-test-binary".into()],
            env: Vec::new(),
            files: Vec::new(),
            cwd: None,
            timeout: std::time::Duration::from_secs(5),
        };
        let e = LocalWorkspace.run(&req).unwrap_err();
        assert_eq!(
            e.message(),
            "command could not be started: entity not found"
        );
    }
}
