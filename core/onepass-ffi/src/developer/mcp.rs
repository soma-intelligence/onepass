//! The MCP server served by the app (spec section 4).
//!
//! MCP clients launch the relay embedded in the app bundle
//! (`Contents/Helpers/onepass-mcp`), which connects to the app's socket.
//! Each connection is one MCP session: the relay's code identity must be
//! the one of the relay file in the app's own bundle, its `hello` names
//! the client (identified by the relay, which sees the client's process
//! chain), and the hardened tools of `onepass-mcp` serve it over the
//! app's session, with the signed policy, the paired client's scopes, the
//! grants, the rate limits, strong authentication and the audit log.
//! Commands and template files go through the relay ([`RelayWorkspace`]),
//! since the sandboxed app cannot reach the user's files.

use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use onepass_core::Id;
use onepass_core::model::Item;
use onepass_core::reference::SecretRef;
use onepass_guard::{
    AuditEntry, AuditLog, AuditSink, OUTCOME_NOT_PAIRED, SignedAuditSink, Surface, SystemClock,
};
use onepass_mcp::runner::{RunOutput, RunRequest};
use onepass_mcp::{
    ClientContext, McpGuards, McpTools, Narrowing, PortError, RepoPort, VaultInfo, VaultPort,
    Workspace, WorkspaceRefusal, file_registry, serve,
};
use onepass_mcp_relay::wire::{
    AppToRelay, ClientHello, Line, LineReader, MAX_WIRE_LINE, RelayToApp, Reply, decode, encode,
};
use onepass_peer::{CodeIdentity, effective_uid, identify_peer, identity_of_file, peer_cred};
use onepass_ssh_agent::bind_socket;
use zeroize::Zeroizing;

use super::admin::{app_policy, exposed_vaults, guard_state, pair};
use super::{
    AUDIT_FILE, CLIENTS_FILE, FfiDeveloperUi, SERVER_STACK, SessionSigner, UiApprover, UiStrong,
    data_dir, guard_account_id, socket_path,
};
use crate::error::{OnePassError, invalid};
use crate::session::Session;

/// An MCP client as its relay identified it (spec 3.2).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMcpClient {
    /// Stable client id (`team:<team>:<identifier>`, `adhoc:<cdhash>`...).
    pub id: String,
    /// Display label (sanitized).
    pub label: String,
    /// The system vouches for its code (platform or team identity).
    pub signed: bool,
    /// The client ids walked from the relay's parent up to the client.
    pub chain: Vec<String>,
}

/// How the app runs its MCP server.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMcpHostConfig {
    /// The data folder (policy, registry, grants, audit log).
    pub data_dir: String,
    /// The socket the relay connects to.
    pub socket_path: String,
    /// The relay file in the app bundle: the only program served.
    pub relay_path: String,
}

/// Whether the peer runs exactly the relay of the app bundle: the same
/// team and identifier for signed code, the same code directory hash for
/// ad hoc code. Platform and unsigned code are never the relay.
pub(crate) fn is_relay(peer: &CodeIdentity, relay: &CodeIdentity) -> bool {
    match (peer, relay) {
        (
            CodeIdentity::Team {
                team_id: a,
                identifier: x,
            },
            CodeIdentity::Team {
                team_id: b,
                identifier: y,
            },
        ) => a == b && x == y,
        (CodeIdentity::AdHoc { cdhash: a, .. }, CodeIdentity::AdHoc { cdhash: b, .. }) => a == b,
        _ => false,
    }
}

/// Who may serve as the relay. Tests inject an identity check; the app
/// compares with the relay file of its bundle.
#[derive(Clone)]
pub(crate) enum RelayCheck {
    /// The peer's code identity must match this one ([`is_relay`]).
    Identity(CodeIdentity),
    /// Tests only: any peer of this user.
    #[cfg(debug_assertions)]
    AnyPeer,
}

/// A running MCP server. `stop` (or dropping it) closes the socket; open
/// sessions end with their relay.
#[derive(uniffi::Object)]
pub struct McpHost {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl McpHost {
    /// Listens on `config.socket_path` for the relay of `config.relay_path`.
    #[uniffi::constructor]
    pub fn start(
        session: Arc<Session>,
        config: FfiMcpHostConfig,
        ui: Arc<dyn FfiDeveloperUi>,
    ) -> Result<Arc<McpHost>, OnePassError> {
        let relay = identity_of_file(Path::new(&config.relay_path))
            .map_err(|_| invalid("program identity"))?;
        McpHost::start_with(session, config, ui, RelayCheck::Identity(relay))
    }

    pub fn socket_path(&self) -> String {
        self.socket.display().to_string()
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|t| !t.is_finished())
    }

    /// Stops accepting and removes the socket.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            let _ = h.join();
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

impl Drop for McpHost {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(debug_assertions)]
impl McpHost {
    /// Tests only (debug builds, never a shipped one; not exported to
    /// Swift): serves any peer of this user
    /// as the relay, so a test can play the relay in process.
    pub fn start_any_relay_for_tests(
        session: Arc<Session>,
        config: FfiMcpHostConfig,
        ui: Arc<dyn FfiDeveloperUi>,
    ) -> Result<Arc<McpHost>, OnePassError> {
        McpHost::start_with(session, config, ui, RelayCheck::AnyPeer)
    }
}

/// Pause between two non-blocking `accept` calls.
const POLL: Duration = Duration::from_millis(100);

/// Everything a connection needs.
#[derive(Clone)]
struct Ctx {
    session: Arc<Session>,
    ui: Arc<dyn FfiDeveloperUi>,
    dir: PathBuf,
    account: String,
    relay: RelayCheck,
}

impl McpHost {
    pub(crate) fn start_with(
        session: Arc<Session>,
        config: FfiMcpHostConfig,
        ui: Arc<dyn FfiDeveloperUi>,
        relay: RelayCheck,
    ) -> Result<Arc<McpHost>, OnePassError> {
        let dir = data_dir(&config.data_dir)?;
        let socket = socket_path(&config.socket_path)?;
        let account = guard_account_id(&session)?;
        // A policy that does not verify stops the server before it serves.
        app_policy(&session, &dir)?;
        AuditLog::open(&dir.join(AUDIT_FILE)).map_err(|_| invalid("audit log"))?;
        let listener = bind_socket(&socket).map_err(|e| match e.kind() {
            io::ErrorKind::AddrInUse => invalid("another agent is serving this socket"),
            _ => invalid("cannot listen on the MCP socket"),
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|_| invalid("cannot listen on the MCP socket"))?;
        let ctx = Ctx {
            session,
            ui,
            dir,
            account,
            relay,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("onepass-mcp".into())
                .stack_size(SERVER_STACK)
                .spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                if stream.set_nonblocking(false).is_err() {
                                    continue;
                                }
                                let ctx = ctx.clone();
                                let _ = thread::Builder::new()
                                    .name("onepass-mcp-conn".into())
                                    .stack_size(SERVER_STACK)
                                    .spawn(move || connection(stream, &ctx));
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => thread::sleep(POLL),
                        }
                    }
                })
                .map_err(|_| invalid("cannot start the MCP server"))?
        };
        Ok(Arc::new(McpHost {
            socket,
            stop,
            thread: Mutex::new(Some(thread)),
        }))
    }
}

/// An audit entry for a connection refused before any tool call.
fn refused(ctx: &Ctx, client: &str, action: &str) {
    if let Ok(log) = AuditLog::open(&ctx.dir.join(AUDIT_FILE)) {
        let mut sink = SignedAuditSink {
            log,
            signer: SessionSigner(ctx.session.clone()),
        };
        let _ = sink.record(&AuditEntry {
            surface: Surface::Mcp,
            client: client.to_owned(),
            client_id: None,
            client_label: None,
            action: action.to_owned(),
            vault_id: None,
            item_id: None,
            field: None,
            decision: "denied".into(),
            outcome: OUTCOME_NOT_PAIRED.into(),
        });
    }
}

/// Whether the peer of `stream` is the app's relay, run by this user.
fn peer_is_relay(stream: &UnixStream, check: &RelayCheck) -> bool {
    let cred = peer_cred(stream);
    if cred.uid != Some(effective_uid()) {
        return false;
    }
    match check {
        RelayCheck::Identity(relay) => {
            identify_peer(&cred).is_ok_and(|peer| is_relay(&peer.code, relay))
        }
        #[cfg(debug_assertions)]
        RelayCheck::AnyPeer => true,
    }
}

/// Serves one relay connection until it closes.
fn connection(stream: UnixStream, ctx: &Ctx) {
    if !peer_is_relay(&stream, &ctx.relay) {
        refused(ctx, "unverified relay", "connect");
        return;
    }
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let writer = Arc::new(Mutex::new(stream));
    let mut lines = LineReader::new(read_half, MAX_WIRE_LINE);
    let hello = match lines.next_line() {
        Ok(Some(Line::Complete(l))) => decode::<RelayToApp>(&l).ok(),
        _ => None,
    };
    let Some(RelayToApp::Hello { client, .. }) = hello else {
        return;
    };
    let client = client.map(|c| admit(ctx, c));
    let context = match client {
        Some(c) => c,
        // Unidentified: served, but no registry entry ever matches it, so
        // every tool call is refused (and audited) by the tools.
        None => ClientContext {
            client_id: "unidentified:relay".into(),
            label: "MCP client (unidentified)".into(),
            signed: false,
            hardened: None,
        },
    };

    // Demultiplexer: MCP lines to the server, results to their requests.
    let (mcp_tx, mcp_rx) = mpsc::channel::<Zeroizing<Vec<u8>>>();
    let pending: Arc<Mutex<HashMap<u64, Sender<RelayToApp>>>> = Arc::default();
    let reader = {
        let pending = pending.clone();
        thread::Builder::new()
            .name("onepass-mcp-read".into())
            .spawn(move || demux(lines, mcp_tx, pending))
    };
    if reader.is_err() {
        return;
    }
    serve_session(ctx, context, mcp_rx, writer.clone(), pending);
    if let Ok(w) = writer.lock() {
        let _ = w.shutdown(std::net::Shutdown::Both);
    }
}

/// Pairs a signed client the registry does not know, if the user agrees
/// (the app checks presence too). Ad hoc and unsigned clients are only
/// paired from the settings, by choosing their file.
fn admit(ctx: &Ctx, hello: ClientHello) -> ClientContext {
    let client = hello.context();
    let known = {
        let state = guard_state(&ctx.dir, &ctx.account);
        let mut loader = state.loader.lock().unwrap_or_else(PoisonError::into_inner);
        loader
            .load(
                &ctx.dir.join(CLIENTS_FILE),
                &SessionSigner(ctx.session.clone()),
                &ctx.account,
            )
            .map(|reg| reg.find(Surface::Mcp, &client.client_id).is_some())
            .unwrap_or(false)
    };
    if !known && client.signed {
        let asked = super::FfiMcpClient {
            id: client.client_id.clone(),
            label: onepass_guard::sanitize_for_display(&client.label),
            signed: true,
            chain: hello.chain.clone(),
        };
        if ctx.ui.pair_request(asked) {
            if let Ok(policy) = app_policy(&ctx.session, &ctx.dir) {
                let _ = pair(&ctx.session, &ctx.dir, &client, hello.code.clone(), &policy);
            }
        } else {
            refused(ctx, &client.label, "pair");
        }
    }
    client
}

fn demux(
    mut lines: LineReader<UnixStream>,
    mcp: Sender<Zeroizing<Vec<u8>>>,
    pending: Arc<Mutex<HashMap<u64, Sender<RelayToApp>>>>,
) {
    while let Ok(Some(Line::Complete(line))) = lines.next_line() {
        let Ok(msg) = decode::<RelayToApp>(&line) else {
            break;
        };
        match msg {
            RelayToApp::Mcp { line } => {
                let mut bytes = Zeroizing::new(Vec::with_capacity(line.len() + 1));
                bytes.extend_from_slice(line.as_bytes());
                bytes.push(b'\n');
                if mcp.send(bytes).is_err() {
                    break;
                }
            }
            RelayToApp::ExecResult { id, .. } | RelayToApp::FileResult { id, .. } => {
                let waiter = pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&id);
                if let Some(w) = waiter {
                    let _ = w.send(msg);
                }
            }
            // A second hello is a protocol error.
            RelayToApp::Hello { .. } => break,
        }
    }
    // Dropping the senders ends the session and every waiting request.
    pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
}

fn serve_session(
    ctx: &Ctx,
    client: ClientContext,
    mcp_rx: Receiver<Zeroizing<Vec<u8>>>,
    writer: Arc<Mutex<UnixStream>>,
    pending: Arc<Mutex<HashMap<u64, Sender<RelayToApp>>>>,
) {
    let Ok(policy) = app_policy(&ctx.session, &ctx.dir) else {
        return;
    };
    let narrowing = Narrowing {
        vaults: Some(exposed_vaults(&policy)),
        scopes: None,
    };
    let Ok(log) = AuditLog::open(&ctx.dir.join(AUDIT_FILE)) else {
        return;
    };
    let sink = SignedAuditSink {
        log,
        signer: SessionSigner(ctx.session.clone()),
    };
    let state = guard_state(&ctx.dir, &ctx.account);
    let guards = McpGuards::new(
        client,
        file_registry(
            ctx.dir.join(CLIENTS_FILE),
            SessionSigner(ctx.session.clone()),
            ctx.account.clone(),
            state.loader.clone(),
        ),
        state.grants.clone(),
        Box::new(SessionSigner(ctx.session.clone())),
        Arc::new(UiStrong(ctx.ui.clone())),
        Arc::new(SystemClock),
    );
    let workspace = RelayWorkspace {
        writer: writer.clone(),
        pending,
        next: AtomicU64::new(1),
    };
    let mut tools = McpTools::new(
        SessionPort(ctx.session.clone()),
        policy,
        narrowing,
        Arc::new(UiApprover {
            ui: ctx.ui.clone(),
            presence: false,
        }),
        Box::new(sink),
        Some(ctx.dir.clone()),
        guards,
    )
    .with_workspace(Box::new(workspace));
    let input = ChannelReader {
        rx: mcp_rx,
        buf: Zeroizing::new(Vec::new()),
        pos: 0,
    };
    let _ = serve(
        &mut tools,
        input,
        McpWriter {
            writer,
            buf: Zeroizing::new(Vec::new()),
        },
    );
}

/// Sends one message to the relay.
fn send(writer: &Mutex<UnixStream>, msg: &AppToRelay) -> io::Result<()> {
    let bytes = encode(msg).map_err(|_| io::Error::other("message too long"))?;
    let mut w = writer.lock().unwrap_or_else(PoisonError::into_inner);
    w.write_all(&bytes)?;
    w.flush()
}

/// The MCP lines of the relay, as the server's input.
struct ChannelReader {
    rx: Receiver<Zeroizing<Vec<u8>>>,
    buf: Zeroizing<Vec<u8>>,
    pos: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for ChannelReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(next) => {
                    self.buf = next;
                    self.pos = 0;
                }
                // The relay closed: end of input.
                Err(_) => return Ok(&[]),
            }
        }
        Ok(&self.buf[self.pos..])
    }

    fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }
}

/// The server's output: each complete line goes to the relay as an `mcp`
/// message.
struct McpWriter {
    writer: Arc<Mutex<UnixStream>>,
    buf: Zeroizing<Vec<u8>>,
}

impl Write for McpWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() + data.len() > MAX_WIRE_LINE {
            return Err(io::Error::other("line too long"));
        }
        self.buf.extend_from_slice(data);
        while let Some(end) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Zeroizing<Vec<u8>> = Zeroizing::new(self.buf.drain(..=end).collect());
            let text = std::str::from_utf8(&line[..line.len() - 1])
                .map_err(|_| io::Error::other("invalid UTF-8"))?;
            send(
                &self.writer,
                &AppToRelay::Mcp {
                    line: Zeroizing::new(text.to_owned()),
                },
            )?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// How long a file request may wait for the relay.
const FILE_WAIT: Duration = Duration::from_secs(30);
/// Margin over a command's own timeout (the relay kills it at the timeout).
const EXEC_MARGIN: Duration = Duration::from_secs(30);

/// [`Workspace`] through the relay: the command runs and the files are
/// read and written in the user's environment, outside the app's sandbox.
struct RelayWorkspace {
    writer: Arc<Mutex<UnixStream>>,
    pending: Arc<Mutex<HashMap<u64, Sender<RelayToApp>>>>,
    next: AtomicU64,
}

impl RelayWorkspace {
    fn ask(
        &self,
        msg: impl FnOnce(u64) -> AppToRelay,
        wait: Duration,
    ) -> Result<RelayToApp, WorkspaceRefusal> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, tx);
        let gone = || WorkspaceRefusal::new("the MCP relay is gone");
        let Ok(bytes) = encode(&msg(id)) else {
            self.pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            return Err(WorkspaceRefusal::new("too large for the MCP relay"));
        };
        let written = {
            let mut w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
            w.write_all(&bytes).and_then(|()| w.flush())
        };
        if written.is_err() {
            self.pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            return Err(gone());
        }
        let reply = rx.recv_timeout(wait).map_err(|_| gone());
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        reply
    }

    fn file(
        &self,
        msg: impl FnOnce(u64) -> AppToRelay,
    ) -> Result<Option<Zeroizing<String>>, WorkspaceRefusal> {
        match self.ask(msg, FILE_WAIT)? {
            RelayToApp::FileResult { result, .. } => match result {
                Reply::Ok(v) => Ok(v),
                Reply::Err(e) => Err(WorkspaceRefusal::new(e)),
            },
            _ => Err(WorkspaceRefusal::new("unexpected relay reply")),
        }
    }
}

fn path_text(p: Option<&Path>) -> Option<String> {
    p.map(|p| p.to_string_lossy().into_owned())
}

impl Workspace for RelayWorkspace {
    fn run(&self, req: &RunRequest) -> Result<RunOutput, WorkspaceRefusal> {
        match self.ask(|id| AppToRelay::exec(id, req), req.timeout + EXEC_MARGIN)? {
            RelayToApp::ExecResult { result, .. } => match result {
                Reply::Ok(out) => Ok(out.into()),
                Reply::Err(e) => Err(WorkspaceRefusal::new(e)),
            },
            _ => Err(WorkspaceRefusal::new("unexpected relay reply")),
        }
    }

    fn read_template(
        &self,
        path: &Path,
        forbidden: Option<&Path>,
    ) -> Result<Zeroizing<String>, WorkspaceRefusal> {
        self.file(|id| AppToRelay::ReadTemplate {
            id,
            path: path.to_string_lossy().into_owned(),
            forbidden: path_text(forbidden),
        })?
        .ok_or_else(|| WorkspaceRefusal::new("unexpected relay reply"))
    }

    fn check_output(
        &self,
        path: &Path,
        overwrite: bool,
        forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal> {
        self.file(|id| AppToRelay::CheckOutput {
            id,
            path: path.to_string_lossy().into_owned(),
            overwrite,
            forbidden: path_text(forbidden),
        })
        .map(|_| ())
    }

    fn write_output(
        &self,
        path: &Path,
        content: &str,
        overwrite: bool,
        forbidden: Option<&Path>,
    ) -> Result<(), WorkspaceRefusal> {
        self.file(|id| AppToRelay::WriteOutput {
            id,
            path: path.to_string_lossy().into_owned(),
            content: Zeroizing::new(content.to_owned()),
            overwrite,
            forbidden: path_text(forbidden),
        })
        .map(|_| ())
    }
}

/// [`VaultPort`] over the app's session: each call is one locked core call.
struct SessionPort(Arc<Session>);

fn port_error(e: OnePassError) -> PortError {
    match e {
        OnePassError::NotFound => PortError::NotFound,
        OnePassError::Integrity { .. } | OnePassError::Crypto => PortError::Integrity,
        OnePassError::Locked => PortError::Other("OnePass is locked".into()),
        other => PortError::Other(other.to_string()),
    }
}

impl SessionPort {
    fn call<T>(
        &mut self,
        f: impl Fn(&mut RepoPort<'_, onepass_core::sync::SyncStore>) -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        let mut out = None;
        self.0
            .with(|repo| {
                out = Some(f(&mut RepoPort(repo)));
                Ok(())
            })
            .map_err(port_error)?;
        out.unwrap_or(Err(PortError::Other("no result".into())))
    }
}

impl VaultPort for SessionPort {
    fn vaults(&mut self) -> Result<Vec<VaultInfo>, PortError> {
        self.call(|p| p.vaults())
    }

    fn items(&mut self, vault_id: Id) -> Result<Vec<Item>, PortError> {
        self.call(|p| p.items(vault_id))
    }

    fn resolve(&mut self, r: &SecretRef) -> Result<Zeroizing<String>, PortError> {
        self.call(|p| p.resolve(r))
    }

    fn save_item(&mut self, vault_id: Id, item: Item) -> Result<(), PortError> {
        self.call(|p| p.save_item(vault_id, item.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_bundled_relay_is_served() {
        let team = |t: &str, i: &str| CodeIdentity::Team {
            team_id: t.into(),
            identifier: i.into(),
        };
        let adhoc = |h: &str| CodeIdentity::AdHoc {
            path: "/x".into(),
            cdhash: h.into(),
            hardened: true,
        };
        let relay = team("2RFY9Z4UVH", "me.somalabs.onepass.mcp-relay");
        assert!(is_relay(
            &team("2RFY9Z4UVH", "me.somalabs.onepass.mcp-relay"),
            &relay
        ));
        assert!(!is_relay(
            &team("OTHERTEAM1", "me.somalabs.onepass.mcp-relay"),
            &relay
        ));
        assert!(!is_relay(
            &team("2RFY9Z4UVH", "me.somalabs.onepass"),
            &relay
        ));
        assert!(!is_relay(&adhoc("ab"), &relay));
        assert!(is_relay(&adhoc("ab"), &adhoc("ab")));
        assert!(!is_relay(&adhoc("ab"), &adhoc("cd")));
        let platform = CodeIdentity::Platform {
            identifier: "com.apple.sh".into(),
        };
        assert!(!is_relay(&platform, &platform));
    }
}
