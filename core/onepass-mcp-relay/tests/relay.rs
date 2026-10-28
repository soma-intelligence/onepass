//! The built relay against a fake app: hello, MCP lines both ways, a
//! command with an injected variable, and the checks of `fill_template`.

use onepass_mcp::MAX_LINE;
use onepass_mcp_relay::wire::{
    AppToRelay, ExecOutput, Line, LineReader, MAX_WIRE_LINE, RelayToApp, Reply, VERSION, decode,
    encode,
};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const RELAY: &str = env!("CARGO_BIN_EXE_onepass-mcp");

fn spawn(socket: &Path) -> Child {
    Command::new(RELAY)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The relay's connection, within 10 seconds.
fn accept(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                return s;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("relay did not connect: {e}"),
        }
    }
}

fn next(reader: &mut LineReader<UnixStream>) -> RelayToApp {
    match reader.next_line().unwrap() {
        Some(Line::Complete(l)) => decode(&l).unwrap(),
        Some(Line::TooLong) => panic!("line too long"),
        None => panic!("relay closed the socket"),
    }
}

fn send(app: &mut UnixStream, msg: &AppToRelay) {
    app.write_all(&encode(msg).unwrap()).unwrap();
}

fn stdout_line(out: &mut BufReader<ChildStdout>) -> String {
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    line
}

#[test]
fn relays_lines_runs_commands_and_checks_files() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("mcp.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let mut child = spawn(&socket);
    let mut app = accept(&listener);
    let mut reader = LineReader::new(app.try_clone().unwrap(), MAX_WIRE_LINE);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // Hello first: the client is the test binary, identified or not.
    let RelayToApp::Hello { v, client, error } = next(&mut reader) else {
        panic!("hello expected");
    };
    assert_eq!(v, VERSION);
    assert!(client.is_some() != error.is_some());

    // Client to app.
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    writeln!(stdin, "{request}").unwrap();
    stdin.flush().unwrap();
    let RelayToApp::Mcp { line } = next(&mut reader) else {
        panic!("mcp expected");
    };
    assert_eq!(*line, request);

    // App to client.
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    send(
        &mut app,
        &AppToRelay::Mcp {
            line: Zeroizing::new(response.into()),
        },
    );
    assert_eq!(stdout_line(&mut stdout), format!("{response}\n"));

    // A line over MAX_LINE gets the server's parse error, locally.
    let mut big = vec![b'x'; MAX_LINE + 10];
    big.push(b'\n');
    stdin.write_all(&big).unwrap();
    stdin.flush().unwrap();
    let error: serde_json::Value = serde_json::from_str(&stdout_line(&mut stdout)).unwrap();
    assert_eq!(error["error"]["code"], -32700);
    assert_eq!(error["error"]["message"], "line too long");

    // A command with an injected variable.
    send(
        &mut app,
        &AppToRelay::Exec {
            id: 1,
            argv: vec!["sh".into(), "-c".into(), r#"printf %s "$TOKEN""#.into()],
            env: vec![("TOKEN".into(), Zeroizing::new("tok-value-8812".into()))],
            files: Vec::new(),
            cwd: None,
            timeout_secs: 20,
        },
    );
    let RelayToApp::ExecResult {
        id: 1,
        result: Reply::Ok(ExecOutput {
            code, stdout: out, ..
        }),
    } = next(&mut reader)
    else {
        panic!("exec_result 1 expected");
    };
    assert_eq!(code, Some(0));
    assert_eq!(*out, "tok-value-8812");

    // fill_template's files: the data directory is refused, the rest done.
    let data = dir.path().join("data");
    fs::create_dir(&data).unwrap();
    let forbidden = Some(data.to_str().unwrap().to_owned());
    let inside = data.join("x.env");
    send(
        &mut app,
        &AppToRelay::WriteOutput {
            id: 2,
            path: inside.to_str().unwrap().into(),
            content: Zeroizing::new("A=1\n".into()),
            overwrite: true,
            forbidden: forbidden.clone(),
        },
    );
    let RelayToApp::FileResult {
        id: 2,
        result: Reply::Err(m),
    } = next(&mut reader)
    else {
        panic!("refused file_result 2 expected");
    };
    assert_eq!(m, "output path is inside the data directory");
    assert!(!inside.exists());

    let template = dir.path().join("t.tpl");
    fs::write(&template, "A={{ onepass://V/I/f }}\n").unwrap();
    send(
        &mut app,
        &AppToRelay::ReadTemplate {
            id: 3,
            path: template.to_str().unwrap().into(),
            forbidden: forbidden.clone(),
        },
    );
    let RelayToApp::FileResult {
        id: 3,
        result: Reply::Ok(Some(text)),
    } = next(&mut reader)
    else {
        panic!("file_result 3 expected");
    };
    assert_eq!(*text, "A={{ onepass://V/I/f }}\n");

    let output = dir.path().join("out.env");
    send(
        &mut app,
        &AppToRelay::CheckOutput {
            id: 4,
            path: output.to_str().unwrap().into(),
            overwrite: false,
            forbidden: forbidden.clone(),
        },
    );
    assert!(matches!(
        next(&mut reader),
        RelayToApp::FileResult {
            id: 4,
            result: Reply::Ok(None)
        }
    ));
    send(
        &mut app,
        &AppToRelay::WriteOutput {
            id: 5,
            path: output.to_str().unwrap().into(),
            content: Zeroizing::new("A=s3cret\n".into()),
            overwrite: false,
            forbidden,
        },
    );
    assert!(matches!(
        next(&mut reader),
        RelayToApp::FileResult {
            id: 5,
            result: Reply::Ok(None)
        }
    ));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::read_to_string(&output).unwrap(), "A=s3cret\n");
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // End of stdin closes the relay's write half; the app then closes.
    drop(stdin);
    assert!(reader.next_line().unwrap().is_none());
    drop(reader);
    drop(app);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut rest).unwrap();
    assert_eq!(rest, "", "stdout carries MCP lines only");
}

#[test]
fn usage_and_unreachable_app() {
    let out = Command::new(RELAY).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: onepass-mcp --socket <path>"));

    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(RELAY)
        .arg("--socket")
        .arg(dir.path().join("none.sock"))
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "onepass-mcp: OnePass is not running or the MCP server is off in its settings\n"
    );
}

#[test]
fn malformed_message_from_the_app_ends_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("mcp.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let child = spawn(&socket);
    let mut app = accept(&listener);
    let mut reader = LineReader::new(app.try_clone().unwrap(), MAX_WIRE_LINE);
    assert!(matches!(next(&mut reader), RelayToApp::Hello { .. }));
    app.write_all(b"{\"t\":\"shell\",\"cmd\":\"true\"}\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "onepass-mcp: malformed message from OnePass\n"
    );
}
