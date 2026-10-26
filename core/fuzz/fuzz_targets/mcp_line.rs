#![no_main]

use libfuzzer_sys::fuzz_target;
use onepass_mcp::{ClientInfo, Session, ToolHost, ToolOutcome, ToolSpec, handle_line};
use serde_json::{Map, Value, json};

/// A host without a vault: fixed tools, fixed outcomes.
struct DummyHost;

impl ToolHost for DummyHost {
    fn tools(&self) -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "echo",
            description: "fixed outcome",
            input_schema: json!({ "type": "object", "additionalProperties": false }),
        }]
    }

    fn call(&mut self, _client: &ClientInfo, name: &str, args: &Map<String, Value>) -> ToolOutcome {
        match (name, args.len() % 3) {
            ("echo", 0) => ToolOutcome::Ok(json!({ "ok": true })),
            ("echo", 1) => ToolOutcome::Refused("refused".into()),
            _ => ToolOutcome::InvalidParams("invalid".into()),
        }
    }
}

// The line comes from an untrusted client: it must never panic the server.
// Run it once on a fresh session and once after a valid `initialize`, so the
// `tools/*` paths are reached too.
fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let mut host = DummyHost;
    let mut fresh = Session::new();
    let _ = handle_line(&mut fresh, &mut host, line);

    let mut ready = Session::new();
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fuzz","version":"0"}}}"#;
    let _ = handle_line(&mut ready, &mut host, init);
    let _ = handle_line(&mut ready, &mut host, line);
});
