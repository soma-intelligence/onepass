//! End-to-end probe of the production bridge, never shipped: a stand-in for
//! the Mac app that serves `BridgeServer` over a fresh throwaway account,
//! approving every pairing at once. Build with `--features dev-fast-kdf`,
//! sign it with the team's identity as `me.somalabs.onepass` (App Group
//! entitlement, no sandbox), then run:
//!
//! `bridge_probe <group container> <scratch dir> [<extension id>...]`
//!
//! It prints `ready` once listening and serves until stdin closes. The relay
//! (Contents/Helpers/onepass-relay of a signed build) and the TypeScript
//! client (`extension/test/bridge/app-relay.test.ts`) do the rest.

use std::io::Read;
use std::sync::{Arc, OnceLock};

use onepass_ffi::*;

struct AutoApprove {
    server: OnceLock<Arc<BridgeServer>>,
}

impl BridgeDelegate for AutoApprove {
    fn pairing_requested(&self, request: FfiBridgePairingRequest) {
        eprintln!(
            "probe: pairing {} ({}) code {}",
            request.browser, request.extension_id, request.code
        );
        if let Some(s) = self.server.get() {
            s.answer_pairing(request.request_id, true);
        }
    }
    fn pairing_ended(&self, _: u64) {}
    fn pairing_stored(&self, p: FfiBridgePairing) {
        eprintln!("probe: pairing stored for {}", p.extension_id);
    }
    fn pairing_used(&self, _: String, _: u64) {}
    fn unlock_requested(&self) {}
    fn confirm_reprompt(&self, _: String, _: String) -> bool {
        false
    }
    fn vault_changed(&self) {
        eprintln!("probe: vault changed");
    }
    fn note(&self, message: String) {
        eprintln!("probe: {message}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(group), Some(scratch)) = (args.first(), args.get(1)) else {
        eprintln!("usage: bridge_probe <group container> <scratch dir> [<extension id>...]");
        std::process::exit(64);
    };
    let db = format!("{scratch}/probe.sqlite");
    let created = create_account_with_kdf(
        db,
        "Probe-Pass-0001".into(),
        FfiKdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        },
    )
    .expect("account");
    let delegate = Arc::new(AutoApprove {
        server: OnceLock::new(),
    });
    let server = BridgeServer::new(
        delegate.clone(),
        Vec::new(),
        args[2..].to_vec(),
        format!("{scratch}/bridge-audit.jsonl"),
    );
    let _ = delegate.server.set(server.clone());
    server.set_session(Some(created.session), "probe@atlas.dev".into());
    if let Err(e) = server.start(group.clone()) {
        eprintln!("probe: cannot start: {e}");
        std::process::exit(1);
    }
    println!("ready");
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    server.stop();
}
