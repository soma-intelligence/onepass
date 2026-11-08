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
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use onepass_core::Id;
use onepass_core::model::Item;
use onepass_core::reference::SecretRef;
use onepass_guard::{
    AuditEntry, AuditLog, AuditSink, OUTCOME_NOT_PAIRED, SignedAuditSink, Surface, SystemClock,
};
use onepass_mcp::runner::{RunOutput, RunRequest};
use onepass_mcp::{
    ClientContext, ClientInfo, McpGuards, McpTools, Narrowing, PolicySource, PortError, RepoPort,
    ToolHost, ToolOutcome, ToolSpec, VaultInfo, VaultPort, Workspace, WorkspaceRefusal,
    file_registry, handle_line, serve_with, tool_specs,
};
use onepass_mcp_relay::wire::{
    AppToRelay, ClientHello, Line, LineReader, MAX_WIRE_LINE, RelayToApp, Reply, decode, encode,
};
use onepass_peer::{CodeIdentity, effective_uid, identify_peer, identity_of_file, peer_cred};
use onepass_ssh_agent::bind_socket;
use zeroize::Zeroizing;

use super::admin::{PairingState, app_policy, audit_admin, exposed_vaults, guard_state, pair};
use super::browser::{HubBrowser, agent_hub};
use super::{
    AUDIT_FILE, CLIENTS_FILE, FfiDeveloperUi, SERVER_STACK, SessionSigner, UiApprover, UiStrong,
    data_dir, guard_account_id, remove_socket, socket_identity, socket_path,
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
    /// Folders no tool may read or write through the relay (the store's
    /// folder; the data folder is always protected).
    pub protected_dirs: Vec<String>,
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
    /// Device and inode of the socket this host bound: `stop` removes only
    /// that file, never a newer host's socket at the same path.
    socket_id: Option<(u64, u64)>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    /// What every connection is served with (connections the gate held
    /// join through [`McpHost::adopt`]).
    ctx: Ctx,
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

    /// Stops accepting, ends every open session (their relays see the
    /// socket close) and removes the socket.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            let _ = h.join();
            remove_socket(&self.socket, self.socket_id);
        }
        for (_, s) in self
            .ctx
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
        {
            let _ = s.shutdown(std::net::Shutdown::Both);
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
/// Most relay sessions served at once; more connections are closed.
const MAX_CONNECTIONS: usize = 16;
/// How long a relay has to send its `hello`.
const HELLO_WAIT: Duration = Duration::from_secs(5);
/// How long a write to the relay may block (a client that stopped reading).
const WRITE_WAIT: Duration = Duration::from_secs(30);
/// MCP lines buffered from the relay while the server is busy (a prompt, a
/// command). The reader never blocks on it (it must keep delivering the
/// results the busy server waits for): a client that sends more than this
/// while the server is busy loses its session.
const LINE_BACKLOG: usize = 64;
/// At most one audit entry per this interval for refused peers.
const REFUSAL_AUDIT_EVERY: Duration = Duration::from_secs(10);

/// The open relay sessions, by connection number, to end them on `stop`.
type Conns = Arc<Mutex<HashMap<u64, UnixStream>>>;
/// Requests sent to the relay and waiting for their result; `None` once
/// the relay is gone.
type Pending = Arc<Mutex<Option<HashMap<u64, Sender<RelayToApp>>>>>;

/// Everything a connection needs.
#[derive(Clone)]
struct Ctx {
    session: Arc<Session>,
    ui: Arc<dyn FfiDeveloperUi>,
    dir: PathBuf,
    account: String,
    relay: RelayCheck,
    protected: Vec<PathBuf>,
    conns: Conns,
    active: Arc<AtomicUsize>,
    /// Number of the last connection.
    next: Arc<AtomicU64>,
    last_refusal_audit: Arc<Mutex<Option<Instant>>>,
}

impl McpHost {
    pub(crate) fn start_with(
        session: Arc<Session>,
        config: FfiMcpHostConfig,
        ui: Arc<dyn FfiDeveloperUi>,
        relay: RelayCheck,
    ) -> Result<Arc<McpHost>, OnePassError> {
        let socket = socket_path(&config.socket_path)?;
        let ctx = prepare(session, &config, ui, relay)?;
        let listener = bind_socket(&socket).map_err(|e| match e.kind() {
            io::ErrorKind::AddrInUse => invalid("another agent is serving this socket"),
            _ => invalid("cannot listen on the MCP socket"),
        })?;
        let socket_id = socket_identity(&socket);
        McpHost::run(listener, socket, socket_id, ctx)
    }

    /// Serves `listener` (bound at `socket`, identity `socket_id`).
    fn run(
        listener: UnixListener,
        socket: PathBuf,
        socket_id: Option<(u64, u64)>,
        ctx: Ctx,
    ) -> Result<Arc<McpHost>, OnePassError> {
        listener
            .set_nonblocking(true)
            .map_err(|_| invalid("cannot listen on the MCP socket"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (stop, ctx) = (stop.clone(), ctx.clone());
            thread::Builder::new()
                .name("onepass-mcp".into())
                .stack_size(SERVER_STACK)
                .spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => accept(stream, &ctx),
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => thread::sleep(POLL),
                        }
                    }
                })
                .map_err(|_| invalid("cannot start the MCP server"))?
        };
        Ok(Arc::new(McpHost {
            socket,
            socket_id,
            stop,
            thread: Mutex::new(Some(thread)),
            ctx,
        }))
    }

    /// Serves a connection the gate held while the app was locked (its
    /// peer verified and its hello read by the gate). Closed when the
    /// server is stopped or full.
    fn adopt(&self, opened: Opened) {
        if self.stop.load(Ordering::SeqCst)
            || self.ctx.active.load(Ordering::SeqCst) >= MAX_CONNECTIONS
        {
            opened.close();
            return;
        }
        let Ok(handle) = opened.stream.try_clone() else {
            opened.close();
            return;
        };
        let id = register(&self.ctx, handle);
        // `stop` sets its flag before it ends the registered connections:
        // either it saw this one, or this sees the flag.
        if self.stop.load(Ordering::SeqCst) {
            unregister(&self.ctx, id);
            opened.close();
            return;
        }
        spawn_registered(&self.ctx, id, move |ctx| serve_opened(opened, ctx));
    }
}

/// Everything the server needs before it listens: fails, without touching
/// any socket, when the policy does not verify or the session is locked.
fn prepare(
    session: Arc<Session>,
    config: &FfiMcpHostConfig,
    ui: Arc<dyn FfiDeveloperUi>,
    relay: RelayCheck,
) -> Result<Ctx, OnePassError> {
    let dir = data_dir(&config.data_dir)?;
    let account = guard_account_id(&session)?;
    // A policy that does not verify stops the server before it serves.
    app_policy(&session, &dir)?;
    AuditLog::open(&dir.join(AUDIT_FILE)).map_err(|_| invalid("audit log"))?;
    Ok(Ctx {
        session,
        ui,
        dir,
        account,
        relay,
        protected: config.protected_dirs.iter().map(PathBuf::from).collect(),
        conns: Arc::default(),
        active: Arc::new(AtomicUsize::new(0)),
        next: Arc::new(AtomicU64::new(0)),
        last_refusal_audit: Arc::default(),
    })
}

/// One accepted connection: refused at once beyond `MAX_CONNECTIONS` or
/// when the peer is not the relay (checked here, before any thread), else
/// served on its own thread and registered until it ends.
fn accept(stream: UnixStream, ctx: &Ctx) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    if ctx.active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
        return;
    }
    if !peer_is_relay(&stream, &ctx.relay) {
        refused_limited(ctx, "unverified relay", "connect");
        return;
    }
    let Ok(handle) = stream.try_clone() else {
        return;
    };
    let id = register(ctx, handle);
    spawn_registered(ctx, id, move |ctx| connection(stream, ctx));
}

/// Registers an open connection (to end it on `stop`); returns its number.
fn register(ctx: &Ctx, handle: UnixStream) -> u64 {
    let id = ctx.next.fetch_add(1, Ordering::SeqCst) + 1;
    ctx.conns
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id, handle);
    ctx.active.fetch_add(1, Ordering::SeqCst);
    id
}

fn unregister(ctx: &Ctx, id: u64) {
    ctx.conns
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
    ctx.active.fetch_sub(1, Ordering::SeqCst);
}

/// Serves the registered connection `id` on its own thread, unregistered
/// when it ends (or at once if no thread starts).
fn spawn_registered(ctx: &Ctx, id: u64, serve: impl FnOnce(&Ctx) + Send + 'static) {
    let conn_ctx = ctx.clone();
    let spawned = thread::Builder::new()
        .name("onepass-mcp-conn".into())
        .stack_size(SERVER_STACK)
        .spawn(move || {
            serve(&conn_ctx);
            unregister(&conn_ctx, id);
        });
    if spawned.is_err() {
        unregister(ctx, id);
    }
}

/// [`refused`], at most once per `REFUSAL_AUDIT_EVERY`: a flood of
/// connections cannot flood the signed log (or hold the session lock).
fn refused_limited(ctx: &Ctx, client: &str, action: &str) {
    {
        let mut last = ctx
            .last_refusal_audit
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|t| t.elapsed() < REFUSAL_AUDIT_EVERY) {
            return;
        }
        *last = Some(Instant::now());
    }
    refused(ctx, client, action);
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
            approved_on: None,
            destination: None,
            namespace: None,
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

/// Serves one relay connection (its peer already verified) until it
/// closes.
fn connection(stream: UnixStream, ctx: &Ctx) {
    if let Some(opened) = open(stream, || {}) {
        serve_opened(opened, ctx);
    }
}

/// A relay connection whose hello was read: the demultiplexer runs, MCP
/// lines wait in `mcp_rx` (at most `LINE_BACKLOG`, more ends it).
pub(crate) struct Opened {
    stream: UnixStream,
    client: Option<ClientHello>,
    mcp_rx: Receiver<Zeroizing<Vec<u8>>>,
    pending: Pending,
    /// The protocol state of a connection whose handshake the gate
    /// answered (`None`: a fresh session).
    proto: Option<onepass_mcp::Session>,
    /// The line the gate held (the first `tools/call`), served first.
    replay: Option<Zeroizing<Vec<u8>>>,
}

impl Opened {
    fn close(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Reads the relay's hello (at most `HELLO_WAIT`), then starts the
/// demultiplexer, which calls `on_end` once the relay is gone (or broke
/// the protocol, or sent too much).
fn open(stream: UnixStream, on_end: impl FnOnce() + Send + 'static) -> Option<Opened> {
    if stream.set_read_timeout(Some(HELLO_WAIT)).is_err()
        || stream.set_write_timeout(Some(WRITE_WAIT)).is_err()
    {
        return None;
    }
    let read_half = stream.try_clone().ok()?;
    let mut lines = LineReader::new(read_half, MAX_WIRE_LINE);
    let hello = match lines.next_line() {
        Ok(Some(Line::Complete(l))) => decode::<RelayToApp>(&l).ok(),
        _ => None,
    };
    let Some(RelayToApp::Hello { client, .. }) = hello else {
        return None;
    };
    // The session itself waits for the client as long as it likes.
    stream.set_read_timeout(None).ok()?;
    // Demultiplexer: MCP lines to the server, results to their requests.
    let (mcp_tx, mcp_rx) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(LINE_BACKLOG);
    let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
    {
        let pending = pending.clone();
        thread::Builder::new()
            .name("onepass-mcp-read".into())
            .spawn(move || {
                demux(lines, mcp_tx, pending);
                on_end();
            })
            .ok()?;
    }
    Some(Opened {
        stream,
        client,
        mcp_rx,
        pending,
        proto: None,
        replay: None,
    })
}

/// Serves an opened connection until it closes.
fn serve_opened(opened: Opened, ctx: &Ctx) {
    let Opened {
        stream,
        client,
        mcp_rx,
        pending,
        proto,
        replay,
    } = opened;
    let writer = Arc::new(Mutex::new(stream));
    // Pairing waits for the user: it runs beside the session, so the
    // client's `initialize` is answered at once. The registry is read again
    // at every tool call, so calls made after the user agreed are served.
    let client = client.map(|c| {
        let context = c.context();
        let (ctx, hello) = (ctx.clone(), c);
        let _ = thread::Builder::new()
            .name("onepass-mcp-pair".into())
            .stack_size(SERVER_STACK)
            .spawn(move || admit(&ctx, hello));
        context
    });
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
    let held = Held {
        proto: proto.unwrap_or_default(),
        replay: replay.unwrap_or_default(),
    };
    serve_session(ctx, context, mcp_rx, writer.clone(), pending, held);
    if let Ok(w) = writer.lock() {
        let _ = w.shutdown(std::net::Shutdown::Both);
    }
}

/// Pairs a signed client the registry does not know, if the user agrees
/// (the app checks presence too). Ad hoc and unsigned clients are only
/// paired from the settings, by choosing their file.
fn admit(ctx: &Ctx, hello: ClientHello) {
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
    if known || !client.signed {
        return;
    }
    // One question at a time per client, and none for a while after a
    // refusal: relaunching the relay in a loop cannot wear the user down.
    let state = guard_state(&ctx.dir, &ctx.account);
    {
        let mut pairing = state.pairing.lock().unwrap_or_else(PoisonError::into_inner);
        match pairing.get(&client.client_id) {
            Some(PairingState::Asking) => return,
            Some(PairingState::RefusedAt(at)) if at.elapsed() < PAIRING_COOLDOWN => return,
            _ => {}
        }
        pairing.insert(client.client_id.clone(), PairingState::Asking);
    }
    let shown = onepass_guard::sanitize_for_display;
    let asked = super::FfiMcpClient {
        id: shown(&client.client_id),
        label: shown(&client.label),
        signed: true,
        chain: hello.chain.iter().take(8).map(|c| shown(c)).collect(),
    };
    let agreed = ctx.ui.pair_request(asked);
    let mut pairing = state.pairing.lock().unwrap_or_else(PoisonError::into_inner);
    if agreed {
        pairing.remove(&client.client_id);
        drop(pairing);
        if let Ok(policy) = app_policy(&ctx.session, &ctx.dir)
            && pair(&ctx.session, &ctx.dir, &client, hello.code.clone(), &policy).is_ok()
        {
            audit_admin(
                &ctx.session,
                &ctx.dir,
                "client_paired",
                Some(&client.label),
                None,
            );
        }
    } else {
        pairing.insert(
            client.client_id.clone(),
            PairingState::RefusedAt(Instant::now()),
        );
        drop(pairing);
        refused(ctx, &client.label, "pair");
    }
}

/// How long a refused pairing stays refused without asking again.
const PAIRING_COOLDOWN: Duration = Duration::from_secs(600);

fn demux(mut lines: LineReader<UnixStream>, mcp: SyncSender<Zeroizing<Vec<u8>>>, pending: Pending) {
    while let Ok(Some(Line::Complete(line))) = lines.next_line() {
        let Ok(msg) = decode::<RelayToApp>(&line) else {
            break;
        };
        match msg {
            RelayToApp::Mcp { line } => {
                let mut bytes = Zeroizing::new(Vec::with_capacity(line.len() + 1));
                bytes.extend_from_slice(line.as_bytes());
                bytes.push(b'\n');
                if mcp.try_send(bytes).is_err() {
                    break;
                }
            }
            RelayToApp::ExecResult { id, .. } | RelayToApp::FileResult { id, .. } => {
                let waiter = pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_mut()
                    .and_then(|p| p.remove(&id));
                if let Some(w) = waiter {
                    let _ = w.send(msg);
                }
            }
            // A second hello is a protocol error.
            RelayToApp::Hello { .. } => break,
        }
    }
    // Dropping the senders ends the session and every waiting request;
    // later requests see the relay gone at once.
    *pending.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

/// Where a session starts: the protocol state and the first input the
/// gate kept for it (fresh and empty for a connection served from the
/// start).
struct Held {
    proto: onepass_mcp::Session,
    replay: Zeroizing<Vec<u8>>,
}

fn serve_session(
    ctx: &Ctx,
    client: ClientContext,
    mcp_rx: Receiver<Zeroizing<Vec<u8>>>,
    writer: Arc<Mutex<UnixStream>>,
    pending: Pending,
    held: Held,
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
    let mut protected = ctx.protected.clone();
    protected.push(ctx.dir.clone());
    let workspace = RelayWorkspace {
        writer: writer.clone(),
        pending,
        protected,
        next: AtomicU64::new(1),
    };
    // The settings may change while the session is open: the policy and
    // the exposed vaults are read again before every call.
    let (session, dir) = (ctx.session.clone(), ctx.dir.clone());
    let policy_source: PolicySource = Box::new(move || {
        let policy = app_policy(&session, &dir).map_err(|e| e.to_string())?;
        let narrowing = Narrowing {
            vaults: Some(exposed_vaults(&policy)),
            scopes: None,
        };
        Ok((policy, narrowing))
    });
    let mut tools = McpTools::new(
        SessionPort(ctx.session.clone()),
        policy,
        narrowing,
        // During an agents-only window the Mac may be unattended: an
        // answer from its panel counts only after Touch ID (a phone answer
        // already carries Face ID).
        Arc::new(UiApprover {
            ui: ctx.ui.clone(),
            presence: ctx.session.agent_window().is_some(),
        }),
        Box::new(sink),
        Some(ctx.dir.clone()),
        guards,
    )
    .with_workspace(Box::new(workspace))
    .with_policy_source(policy_source)
    // The bridge serves the same hub to the extension (`agent_wait`).
    .with_browser(Box::new(HubBrowser { hub: agent_hub() }));
    let input = ChannelReader {
        rx: mcp_rx,
        buf: held.replay,
        pos: 0,
    };
    let _ = serve_with(
        held.proto,
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
    pending: Pending,
    /// The data folder and the store's folder: never read nor written.
    protected: Vec<PathBuf>,
    next: AtomicU64,
}

impl RelayWorkspace {
    fn forget(&self, id: u64) {
        if let Some(p) = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            p.remove(&id);
        }
    }

    fn ask(
        &self,
        msg: impl FnOnce(u64) -> AppToRelay,
        wait: Duration,
    ) -> Result<RelayToApp, WorkspaceRefusal> {
        let gone = || WorkspaceRefusal::new("the MCP relay is gone");
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        match self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            Some(p) => p.insert(id, tx),
            None => return Err(gone()),
        };
        let Ok(bytes) = encode(&msg(id)) else {
            self.forget(id);
            return Err(WorkspaceRefusal::new("too large for the MCP relay"));
        };
        let written = {
            let mut w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
            w.write_all(&bytes).and_then(|()| w.flush())
        };
        if written.is_err() {
            self.forget(id);
            return Err(gone());
        }
        let reply = rx.recv_timeout(wait).map_err(|_| gone());
        self.forget(id);
        reply
    }

    /// Refuses a path inside a protected folder before the relay sees it.
    /// Lexical (the relay resolves links and checks the data folder again,
    /// see `forbidden`): it stops an agent from naming the store's file.
    fn check_protected(&self, path: &Path) -> Result<(), WorkspaceRefusal> {
        let path = normalize(path);
        if self
            .protected
            .iter()
            .any(|p| path.starts_with(normalize(p)))
        {
            return Err(WorkspaceRefusal::new(
                "refused: inside the OnePass data folder",
            ));
        }
        Ok(())
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

/// `path` made absolute against nothing (relative paths stay relative)
/// with `.` dropped and `..` applied, lexically.
fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
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
        self.check_protected(path)?;
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
        self.check_protected(path)?;
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
        self.check_protected(path)?;
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

// ---- the gate, while the app is locked (spec 6.2)

/// What an agent is told when the app stays locked. No secret, no name.
pub const MCP_LOCKED_MESSAGE: &str =
    "OnePass is locked on this Mac. Approve on your iPhone or unlock the app.";
/// What a client the registry does not list is told while the app is
/// locked: pairing needs the owner at the Mac, the phone is not asked.
pub const MCP_NOT_PAIRED_LOCKED_MESSAGE: &str =
    "This client is not paired with OnePass. Unlock OnePass on this Mac to pair it.";
/// JSON-RPC code of that error (implementation-defined server error).
const LOCKED_CODE: i64 = -32000;
/// How long a refused connection waits for the agent's first request, to
/// answer it by its id (a `null` id after that).
const LOCKED_REPLY_WAIT: Duration = Duration::from_secs(5);
/// How long a connection the app said yes to waits for `hand_over`.
const HAND_OVER_WAIT: Duration = Duration::from_secs(30);
/// How long a connection beyond `MAX_CONNECTIONS` may take to receive its
/// locked error.
const OVERFLOW_WRITE_WAIT: Duration = Duration::from_secs(1);

/// The app's side of the gate.
#[uniffi::export(with_foreign)]
pub trait FfiGateUi: Send + Sync {
    /// A paired agent called its first tool while the app is locked (the
    /// gate answered `initialize` and `tools/list` itself: a client that
    /// never calls a tool asks nothing). Called on a gate thread; blocks
    /// until the app knows. True once a session exists and the app called
    /// (or is about to call) [`McpGate::hand_over`]: the connection then
    /// goes to the server, which answers that call. False refuses: the
    /// agent gets [`MCP_LOCKED_MESSAGE`] and the connection closes.
    ///
    /// The app answers within 60 s (spec 6.2: no answer from the phone or
    /// the Mac in 60 s is a refusal), and false at the latest then. The
    /// gate does not wait on it to free the client: a client that leaves
    /// while held releases its hold at once, and a late answer for it is
    /// dropped.
    fn locked_request(&self, client: FfiMcpClient) -> bool;
}

enum GateState {
    /// Listening, holding connections.
    Holding,
    /// The socket went to this server.
    Handed(Weak<McpHost>),
    /// Stopped while locked: held connections are refused.
    Stopped,
}

struct GateShared {
    ui: Arc<dyn FfiGateUi>,
    relay: RelayCheck,
    /// The data folder: its client registry says who is paired.
    dir: PathBuf,
    /// Client id to the number of the connection asking for it: one
    /// question per client.
    held: Mutex<HashMap<String, u64>>,
    /// Open connections, to end them on `stop`.
    conns: Conns,
    active: AtomicUsize,
    next: AtomicU64,
    state: Mutex<GateState>,
    changed: Condvar,
}

/// Where the gate stands for a connection still in its handshake.
enum Standing {
    Holding,
    Handed(Option<Arc<McpHost>>),
    Stopped,
}

impl GateShared {
    /// Frees the hold of connection `number`, if it has one.
    fn release(&self, number: u64) {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, n| *n != number);
    }

    fn standing(&self) -> Standing {
        match &*self.state.lock().unwrap_or_else(PoisonError::into_inner) {
            GateState::Holding => Standing::Holding,
            GateState::Handed(host) => Standing::Handed(host.upgrade()),
            GateState::Stopped => Standing::Stopped,
        }
    }

    /// The server the socket went to, waiting at most `HAND_OVER_WAIT`.
    fn handed_host(&self) -> Option<Arc<McpHost>> {
        let deadline = Instant::now() + HAND_OVER_WAIT;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match &*state {
                GateState::Handed(host) => return host.upgrade(),
                GateState::Stopped => return None,
                GateState::Holding => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Stopped: held connections are refused, and those in their
    /// handshake end.
    fn set_stopped(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = GateState::Stopped;
        self.changed.notify_all();
        for (_, s) in self
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
        {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Listens on the MCP socket while the app is locked: verifies the peer
/// like the server, reads the hello, answers the MCP handshake itself
/// (`initialize`, `tools/list`, `ping`, as the server would), and on the
/// first `tools/call` of a paired client asks the app ([`FfiGateUi`]). It
/// then hands the connection to the server started on the session, which
/// answers that call, or answers [`MCP_LOCKED_MESSAGE`] and closes.
#[derive(uniffi::Object)]
pub struct McpGate {
    socket: PathBuf,
    socket_id: Option<(u64, u64)>,
    stop: Arc<AtomicBool>,
    /// The accept loop; gives the listener back when it stops.
    thread: Mutex<Option<JoinHandle<UnixListener>>>,
    shared: Arc<GateShared>,
}

#[uniffi::export]
impl McpGate {
    /// Listens on `socket_path` for the relay of `relay_path`; `data_dir`
    /// is the data folder of the server (its client registry).
    #[uniffi::constructor]
    pub fn start(
        socket_path: String,
        relay_path: String,
        data_dir: String,
        ui: Arc<dyn FfiGateUi>,
    ) -> Result<Arc<McpGate>, OnePassError> {
        let relay =
            identity_of_file(Path::new(&relay_path)).map_err(|_| invalid("program identity"))?;
        McpGate::start_with(socket_path, data_dir, ui, RelayCheck::Identity(relay))
    }

    /// The app has a session (full or agents only): starts the MCP server
    /// on it, on the gate's own socket (no moment without a listener), and
    /// gives it the connections still in their handshake and those the app
    /// says yes to. On an error before the listener moves (a policy that
    /// does not verify, a locked session) the gate keeps listening; if the
    /// server then fails to start, the gate stops (held connections are
    /// refused) and the socket is removed. `config.socket_path` must be the
    /// gate's socket; the relay check is the gate's (`config.relay_path` is
    /// not read again).
    pub fn hand_over(
        &self,
        session: Arc<Session>,
        config: FfiMcpHostConfig,
        ui: Arc<dyn FfiDeveloperUi>,
    ) -> Result<Arc<McpHost>, OnePassError> {
        if socket_path(&config.socket_path)? != self.socket {
            return Err(invalid("not the gate's socket"));
        }
        let ctx = prepare(session, &config, ui, self.shared.relay.clone())?;
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(handle) = handle else {
            return Err(invalid("the gate is not running"));
        };
        self.stop.store(true, Ordering::SeqCst);
        let started = handle
            .join()
            .map_err(|_| invalid("cannot start the MCP server"))
            .and_then(|listener| McpHost::run(listener, self.socket.clone(), self.socket_id, ctx));
        let host = match started {
            Ok(host) => host,
            Err(e) => {
                remove_socket(&self.socket, self.socket_id);
                self.shared.set_stopped();
                return Err(e);
            }
        };
        *self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = GateState::Handed(Arc::downgrade(&host));
        self.shared.changed.notify_all();
        Ok(host)
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|t| !t.is_finished())
    }

    /// Stops listening and removes the socket. Before a hand-over, held
    /// connections are refused; after it, they still go to the server
    /// once the app answers (the gate can be dropped right after
    /// `hand_over`).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            drop(h.join());
            remove_socket(&self.socket, self.socket_id);
        }
        if matches!(
            *self
                .shared
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            GateState::Handed(_)
        ) {
            return;
        }
        self.shared.set_stopped();
    }
}

impl Drop for McpGate {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(debug_assertions)]
impl McpGate {
    /// Tests only (debug builds, not exported to Swift): any peer of this
    /// user is the relay.
    pub fn start_any_relay_for_tests(
        socket_path: String,
        data_dir: String,
        ui: Arc<dyn FfiGateUi>,
    ) -> Result<Arc<McpGate>, OnePassError> {
        McpGate::start_with(socket_path, data_dir, ui, RelayCheck::AnyPeer)
    }
}

impl McpGate {
    fn start_with(
        socket_path_text: String,
        data_dir: String,
        ui: Arc<dyn FfiGateUi>,
        relay: RelayCheck,
    ) -> Result<Arc<McpGate>, OnePassError> {
        let socket = socket_path(&socket_path_text)?;
        let dir = self::data_dir(&data_dir)?;
        let listener = bind_socket(&socket).map_err(|e| match e.kind() {
            io::ErrorKind::AddrInUse => invalid("another agent is serving this socket"),
            _ => invalid("cannot listen on the MCP socket"),
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|_| invalid("cannot listen on the MCP socket"))?;
        let socket_id = socket_identity(&socket);
        let shared = Arc::new(GateShared {
            ui,
            relay,
            dir,
            held: Mutex::default(),
            conns: Arc::default(),
            active: AtomicUsize::new(0),
            next: AtomicU64::new(0),
            state: Mutex::new(GateState::Holding),
            changed: Condvar::new(),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (stop, shared) = (stop.clone(), shared.clone());
            thread::Builder::new()
                .name("onepass-mcp-gate".into())
                .stack_size(SERVER_STACK)
                .spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => gate_accept(stream, &shared),
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => thread::sleep(POLL),
                        }
                    }
                    listener
                })
                .map_err(|_| {
                    remove_socket(&socket, socket_id);
                    invalid("cannot start the MCP gate")
                })?
        };
        Ok(Arc::new(McpGate {
            socket,
            socket_id,
            stop,
            thread: Mutex::new(Some(thread)),
            shared,
        }))
    }
}

/// One connection to the gate: beyond `MAX_CONNECTIONS` it gets the
/// locked error (no request id yet) and closes; a peer that is not the
/// relay is closed without a word (no audit entry: there is no session to
/// sign it with); else it is held on its own thread.
fn gate_accept(stream: UnixStream, shared: &Arc<GateShared>) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    if shared.active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
        if stream.set_write_timeout(Some(OVERFLOW_WRITE_WAIT)).is_ok() {
            write_error(&stream, serde_json::Value::Null, MCP_LOCKED_MESSAGE);
        }
        return;
    }
    if !peer_is_relay(&stream, &shared.relay) {
        return;
    }
    let Ok(handle) = stream.try_clone() else {
        return;
    };
    let number = shared.next.fetch_add(1, Ordering::SeqCst) + 1;
    shared
        .conns
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(number, handle);
    shared.active.fetch_add(1, Ordering::SeqCst);
    let end = move |shared: &GateShared| {
        shared
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&number);
        shared.active.fetch_sub(1, Ordering::SeqCst);
    };
    let conn_shared = shared.clone();
    let spawned = thread::Builder::new()
        .name("onepass-mcp-held".into())
        .stack_size(SERVER_STACK)
        .spawn(move || {
            hold(stream, &conn_shared, number);
            end(&conn_shared);
        });
    if spawned.is_err() {
        end(shared);
    }
}

/// The tools as the server lists them; nothing is called through it (the
/// gate keeps every `tools/call` for the server).
struct GateTools;

impl ToolHost for GateTools {
    fn tools(&self) -> Vec<ToolSpec> {
        tool_specs()
    }

    fn call(
        &mut self,
        _client: &ClientInfo,
        _name: &str,
        _args: &serde_json::Map<String, serde_json::Value>,
    ) -> ToolOutcome {
        ToolOutcome::Refused(MCP_LOCKED_MESSAGE.into())
    }
}

/// One MCP line read by the gate.
enum GateLine {
    /// Answered here (`None`: a notification, or blank).
    Answer(Option<String>),
    /// The first tool call of an initialized client, with its id: kept for
    /// the server.
    Call(serde_json::Value),
}

fn gate_line(proto: &mut onepass_mcp::Session, line: &[u8]) -> GateLine {
    let Ok(text) = std::str::from_utf8(line) else {
        return GateLine::Answer(Some(
            serde_json::json!({"jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": "invalid UTF-8"}})
            .to_string(),
        ));
    };
    let text = text.trim_end_matches(['\n', '\r']);
    if text.trim().is_empty() {
        return GateLine::Answer(None);
    }
    if proto.is_initialized()
        && let Ok(msg) = serde_json::from_str::<serde_json::Value>(text)
        && msg.get("method").and_then(serde_json::Value::as_str) == Some("tools/call")
        && let Some(id) = msg.get("id").filter(|i| i.is_string() || i.is_number())
    {
        return GateLine::Call(id.clone());
    }
    GateLine::Answer(handle_line(proto, &mut GateTools, text))
}

/// Holds one connection: answers its handshake, then asks the app on its
/// first tool call. A hand-over (the owner unlocked, or an agents-only
/// window opened for another client) takes the connection to the server
/// as it stands.
fn hold(stream: UnixStream, shared: &Arc<GateShared>, number: u64) {
    let gone = Arc::new(AtomicBool::new(false));
    let on_end = {
        let (shared, gone) = (shared.clone(), gone.clone());
        move || {
            gone.store(true, Ordering::SeqCst);
            shared.release(number);
        }
    };
    let Some(mut opened) = open(stream, on_end) else {
        return;
    };
    // An unidentified client could not be served anyway: nothing to ask.
    let Some(hello) = opened.client.clone() else {
        answer_locked(&opened);
        return;
    };
    let mut proto = onepass_mcp::Session::new();
    let (line, id) = loop {
        match shared.standing() {
            Standing::Holding => {}
            Standing::Handed(Some(host)) => {
                opened.proto = Some(proto);
                host.adopt(opened);
                return;
            }
            Standing::Handed(None) | Standing::Stopped => {
                opened.close();
                return;
            }
        }
        let line = match opened.mcp_rx.recv_timeout(POLL) {
            Ok(line) => line,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            // The relay left (or the gate stopped and closed it).
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                opened.close();
                return;
            }
        };
        match gate_line(&mut proto, &line) {
            GateLine::Answer(None) => {}
            GateLine::Answer(Some(reply)) => {
                if !write_line(&opened.stream, reply) {
                    opened.close();
                    return;
                }
            }
            GateLine::Call(id) => break (line, id),
        }
    };
    // Handed over while the call came in: the server answers it.
    match shared.standing() {
        Standing::Holding => {}
        Standing::Handed(Some(host)) => {
            opened.proto = Some(proto);
            opened.replay = Some(line);
            host.adopt(opened);
            return;
        }
        Standing::Handed(None) | Standing::Stopped => {
            write_error(&opened.stream, id, MCP_LOCKED_MESSAGE);
            opened.close();
            return;
        }
    }
    // Pairing needs the owner at the Mac: an unlisted client asks no phone.
    if !onepass_guard::listed_unverified(&shared.dir.join(CLIENTS_FILE), Surface::Mcp, &hello.id) {
        write_error(&opened.stream, id, MCP_NOT_PAIRED_LOCKED_MESSAGE);
        opened.close();
        return;
    }
    {
        let mut held = shared.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.contains_key(&hello.id) {
            drop(held);
            write_error(&opened.stream, id, MCP_LOCKED_MESSAGE);
            opened.close();
            return;
        }
        held.insert(hello.id.clone(), number);
    }
    // Left between the call and the hold: nobody to ask for.
    if gone.load(Ordering::SeqCst) {
        shared.release(number);
        opened.close();
        return;
    }
    let shown = onepass_guard::sanitize_for_display;
    let asked = FfiMcpClient {
        id: shown(&hello.id),
        label: shown(&hello.label),
        signed: hello.signed,
        chain: hello.chain.iter().take(8).map(|c| shown(c)).collect(),
    };
    let unlocked = shared.ui.locked_request(asked);
    let host = if unlocked && !gone.load(Ordering::SeqCst) {
        shared.handed_host()
    } else {
        None
    };
    // Released only now: a hand-over that comes late cannot let a second
    // connection of this client ask again meanwhile.
    shared.release(number);
    if gone.load(Ordering::SeqCst) {
        // The client left while the app decided: the answer serves nobody.
        opened.close();
        return;
    }
    if let Some(host) = host {
        opened.proto = Some(proto);
        opened.replay = Some(line);
        host.adopt(opened);
        return;
    }
    write_error(&opened.stream, id, MCP_LOCKED_MESSAGE);
    opened.close();
}

/// Writes one MCP line to the relay; false when it failed.
fn write_line(stream: &UnixStream, line: String) -> bool {
    let Ok(bytes) = encode(&AppToRelay::Mcp {
        line: Zeroizing::new(line),
    }) else {
        return false;
    };
    let mut w = stream;
    w.write_all(&bytes).and_then(|()| w.flush()).is_ok()
}

/// A JSON-RPC error with `message` for request `id`.
fn write_error(stream: &UnixStream, id: serde_json::Value, message: &str) {
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": LOCKED_CODE, "message": message},
    });
    let _ = write_line(stream, reply.to_string());
}

/// Answers the agent's first request (or `null` if none comes in time)
/// with [`MCP_LOCKED_MESSAGE`], then closes.
fn answer_locked(opened: &Opened) {
    let deadline = Instant::now() + LOCKED_REPLY_WAIT;
    let mut id = serde_json::Value::Null;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let Ok(line) = opened.mcp_rx.recv_timeout(left) else {
            break;
        };
        // Notifications have no id and get no answer.
        if let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&line)
            && msg.get("method").is_some()
            && let Some(request) = msg.get("id")
        {
            id = request.clone();
            break;
        }
    }
    write_error(&opened.stream, id, MCP_LOCKED_MESSAGE);
    opened.close();
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
        let relay = team("ABCDE12345", "me.somalabs.onepass.mcp-relay");
        assert!(is_relay(
            &team("ABCDE12345", "me.somalabs.onepass.mcp-relay"),
            &relay
        ));
        assert!(!is_relay(
            &team("OTHERTEAM1", "me.somalabs.onepass.mcp-relay"),
            &relay
        ));
        assert!(!is_relay(
            &team("ABCDE12345", "me.somalabs.onepass"),
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
