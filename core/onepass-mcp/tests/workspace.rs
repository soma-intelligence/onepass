//! Secret tools over a replaced [`Workspace`]: the tools hand it the
//! command and the files, and still mask what comes back.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use onepass_guard::Decision;
use onepass_guard::testing::ScriptedApprover;
use onepass_mcp::runner::{RunOutput, RunRequest};
use onepass_mcp::{Narrowing, Policy, Workspace, WorkspaceRefusal};
use serde_json::json;
use zeroize::Zeroizing;

/// What the scripted workspace was asked.
#[derive(Default)]
struct Seen {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    files: Vec<(String, String)>,
    cwd: Option<PathBuf>,
    timeout: Option<Duration>,
    templates: Vec<(PathBuf, Option<PathBuf>)>,
    checks: Vec<(PathBuf, bool)>,
    writes: Vec<(PathBuf, String, bool, Option<PathBuf>)>,
}

/// A workspace that records its requests, answers every run with the
/// injected values echoed back, serves one template and refuses writes
/// when `refuse_write` is set.
struct Scripted {
    seen: Arc<Mutex<Seen>>,
    template: &'static str,
    refuse_write: Option<&'static str>,
}

impl Workspace for Scripted {
    fn run(&self, req: &RunRequest) -> Result<RunOutput, WorkspaceRefusal> {
        let mut s = self.seen.lock().unwrap();
        s.argv = req.argv.clone();
        s.env = req
            .env
            .iter()
            .map(|(n, v)| (n.clone(), v.as_str().to_owned()))
            .collect();
        s.files = req
            .files
            .iter()
            .map(|(n, v)| (n.clone(), v.as_str().to_owned()))
            .collect();
        s.cwd = req.cwd.clone();
        s.timeout = Some(req.timeout);
        let echoed: Vec<&str> = req
            .env
            .iter()
            .chain(&req.files)
            .map(|(_, v)| v.as_str())
            .collect();
        Ok(RunOutput {
            code: Some(7),
            stdout: Zeroizing::new(format!("got {}", echoed.join(","))),
            stderr: Zeroizing::new(format!("err {}", echoed.join(","))),
            timed_out: false,
            truncated: true,
        })
    }

    fn read_template(
        &self,
        path: &Path,
        forbidden: Option<&Path>,
    ) -> Result<Zeroizing<String>, WorkspaceRefusal> {
        self.seen
            .lock()
            .unwrap()
            .templates
            .push((path.to_path_buf(), forbidden.map(Path::to_path_buf)));
        Ok(Zeroizing::new(self.template.to_owned()))
    }

    fn check_output(
        &self,
        path: &Path,
        overwrite: bool,
        _forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal> {
        self.seen
            .lock()
            .unwrap()
            .checks
            .push((path.to_path_buf(), overwrite));
        Ok(())
    }

    fn write_output(
        &self,
        path: &Path,
        content: &str,
        overwrite: bool,
        forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal> {
        self.seen.lock().unwrap().writes.push((
            path.to_path_buf(),
            content.to_owned(),
            overwrite,
            forbidden.map(Path::to_path_buf),
        ));
        match self.refuse_write {
            Some(m) => Err(WorkspaceRefusal::new(m)),
            None => Ok(()),
        }
    }
}

fn scripted_tools(
    template: &'static str,
    refuse_write: Option<&'static str>,
    forbidden: Option<PathBuf>,
) -> (Tools, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let approver = Arc::new(ScriptedApprover::new(vec![Decision::AllowOnce]));
    let (t, _) = tools_full(
        |_| Policy::default_for(&account_id()),
        |_| Narrowing::default(),
        approver,
        forbidden,
    );
    let t = t.with_workspace(Box::new(Scripted {
        seen: seen.clone(),
        template,
        refuse_write,
    }));
    (t, seen)
}

#[test]
fn run_goes_through_the_workspace_and_is_masked() {
    let (mut t, seen) = scripted_tools("", None, None);
    let v = ok(call(
        &mut t,
        "run_with_secrets",
        json!({
            "command": ["deploy", "--now"],
            "env": {"TOKEN": "onepass://Dev/GitHub/password"},
            "files": {"USERFILE": "onepass://Dev/GitHub/username"},
            "cwd": "/srv/app",
            "timeout_secs": 9,
        }),
    ));
    {
        let s = seen.lock().unwrap();
        assert_eq!(s.argv, ["deploy", "--now"]);
        assert_eq!(s.env, [("TOKEN".to_owned(), GITHUB_PW.to_owned())]);
        assert_eq!(s.files, [("USERFILE".to_owned(), GITHUB_USER.to_owned())]);
        assert_eq!(s.cwd.as_deref(), Some(Path::new("/srv/app")));
        assert_eq!(s.timeout, Some(Duration::from_secs(9)));
    }
    let text = v.to_string();
    assert!(
        !text.contains(GITHUB_PW) && !text.contains(GITHUB_USER),
        "{text}"
    );
    assert_eq!(v["stdout"], "got <concealed:TOKEN>,<concealed:USERFILE>");
    assert_eq!(v["stderr"], "err <concealed:TOKEN>,<concealed:USERFILE>");
    assert_eq!(v["exit_code"], 7);
    assert_eq!(v["timed_out"], false);
    assert_eq!(v["truncated"], true);
}

#[test]
fn run_refused_by_the_workspace_is_a_tool_refusal() {
    struct Refusing;
    impl Workspace for Refusing {
        fn run(&self, _req: &RunRequest) -> Result<RunOutput, WorkspaceRefusal> {
            Err(WorkspaceRefusal::new(
                "command could not be started: entity not found",
            ))
        }
        fn read_template(
            &self,
            _: &Path,
            _: Option<&Path>,
        ) -> Result<Zeroizing<String>, WorkspaceRefusal> {
            unreachable!()
        }
        fn check_output(
            &self,
            _: &Path,
            _: bool,
            _: Option<&Path>,
        ) -> Result<(), WorkspaceRefusal> {
            unreachable!()
        }
        fn write_output(
            &self,
            _: &Path,
            _: &str,
            _: bool,
            _: Option<&Path>,
        ) -> Result<(), WorkspaceRefusal> {
            unreachable!()
        }
    }
    let approver = Arc::new(ScriptedApprover::new(vec![Decision::AllowOnce]));
    let mut t =
        tools(Policy::default_for(&account_id()), approver).with_workspace(Box::new(Refusing));
    let m = refused(call(
        &mut t,
        "run_with_secrets",
        json!({"command": ["x"], "env": {"T": "onepass://Dev/GitHub/password"}}),
    ));
    assert_eq!(m, "command could not be started: entity not found");
}

#[test]
fn fill_template_write_refused_by_the_workspace_is_a_tool_refusal() {
    let data = PathBuf::from("/data-dir");
    let (mut t, seen) = scripted_tools(
        "PW={{ onepass://Dev/GitHub/password }}\n",
        Some("output could not be written: permission denied"),
        Some(data.clone()),
    );
    let m = refused(call(
        &mut t,
        "fill_template",
        json!({"template_path": "/in/app.env.tpl", "output_path": "/out/app.env", "overwrite": true}),
    ));
    assert_eq!(m, "output could not be written: permission denied");
    let s = seen.lock().unwrap();
    assert_eq!(
        s.templates,
        [(PathBuf::from("/in/app.env.tpl"), Some(data.clone()))]
    );
    // Checked before anyone is asked, then checked again by the write.
    assert_eq!(s.checks, [(PathBuf::from("/out/app.env"), true)]);
    assert_eq!(s.writes.len(), 1);
    let (path, content, overwrite, forbidden) = &s.writes[0];
    assert_eq!(path, Path::new("/out/app.env"));
    assert_eq!(content, &format!("PW={GITHUB_PW}\n"));
    assert!(*overwrite);
    assert_eq!(forbidden.as_deref(), Some(data.as_path()));
}

/// A host whose settings change while a session is open: the policy source
/// is read again before every call, and a failed read exposes nothing.
#[test]
fn the_policy_source_applies_to_the_next_call() {
    use std::sync::atomic::{AtomicU8, Ordering};
    let (t, _) = scripted_tools("", None, None);
    let state = Arc::new(AtomicU8::new(0));
    let s = state.clone();
    let mut t = t.with_policy_source(Box::new(move || match s.load(Ordering::SeqCst) {
        0 => Ok((Policy::default_for(&account_id()), Narrowing::default())),
        1 => Ok((
            Policy::default_for(&account_id()),
            Narrowing {
                vaults: Some(Default::default()),
                scopes: None,
            },
        )),
        _ => Err("tampered".into()),
    }));
    let listed = ok(call(&mut t, "list_vaults", json!({})));
    assert!(
        !listed["untrusted_vault_data"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{listed}"
    );
    for next in [1, 2] {
        state.store(next, Ordering::SeqCst);
        let listed = ok(call(&mut t, "list_vaults", json!({})));
        assert!(
            listed["untrusted_vault_data"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{listed}"
        );
    }
}
