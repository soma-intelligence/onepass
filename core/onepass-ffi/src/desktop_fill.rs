//! The Mac fill helper's client of the bridge (spec
//! `docs/superpowers/specs/2026-11-23-mac-fill-anywhere-design.md`,
//! `BridgeClient`).
//!
//! "OnePass Fill" is a client of the app's `bridge.sock`, like the
//! browsers: the same pairing, session and encrypted channel as the
//! extension (`onepass-bridge`), the app checking the helper's code
//! signature and the helper checking the app's. The socket admits the
//! helper as the fill client, vouched by its signature: it pairs without a
//! code, and its session speaks the `desktop` context only (plus `status`).
//!
//! The helper keeps no secret and no vault cache. The only persistent
//! value is its pairing record, opaque bytes the helper keeps in its own
//! keychain item (`FillPairingStore`). A fill asks for one field of the
//! picked login, and the value comes back in a `FfiSecretValue`, wiped on
//! drop on the Rust side.
//!
//! One connection is kept open and reused. A read (`status`, `unlock`, the
//! lists) that finds the connection closed (an idle session, an app
//! restart) opens it again and is sent once more; a `fill` never is: the
//! app may have served it already, so a lost fill is `AppClosed`. A
//! stored pairing the app no longer knows (forgotten in Settings) makes the
//! next connection pair again and save the new record.
//!
//! Errors (`OnePassError`):
//! - `Locked`: the vault is locked (`status` says `Locked`).
//! - `NotFound`: no such login, or the login has no value for the field.
//! - `AppClosed`: no socket, refused, or the connection was lost.
//! - `Validation { field: "bridge", reason }`: anything else of the bridge.
//!   `reason` is `untrusted_app` (the socket is not held by the OnePass app of
//!   this team), `protocol` (an answer the protocol does not allow), or
//!   the app's own error code (`not_allowed`, `invalid`, `reprompt_required`
//!   and so on, see `onepass_bridge::AppErrorCode`).

use std::io::{self, ErrorKind};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use onepass_bridge::BridgeError;
use onepass_bridge::api::{Ctx, FillField, Request, SecretString, Summary};
use onepass_bridge::channel::Channel;
use onepass_bridge::framing::{read_frame, write_frame};
use onepass_bridge::origin::MatchQuality;
use onepass_bridge::pairing::{ExtPairing, PairingRecord};
use onepass_bridge::session;
use onepass_bridge::wire::{self, Envelope};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::OnePassError;

/// The helper's opening frame on the socket: protocol version 1, no
/// extension id, no launcher (the socket fixes the helper's extension id).
const OPENING: &[u8] = br#"{"onepass_relay":1}"#;
/// The names the helper pairs under (the app stores its own verified name,
/// "OnePass Fill", next to them).
const EXT_NAME: &str = "OnePass Fill";
const PLATFORM: &str = "macOS";
/// Longest wait for one answer: a fill may wait for Touch ID in the app.
const READ_TIMEOUT: Duration = Duration::from_secs(130);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Version byte of the stored pairing record.
const RECORD_V1: u8 = 1;

/// Where the helper keeps its pairing record (its own keychain item).
/// The bytes are opaque: store them as given, return them unchanged.
#[uniffi::export(with_foreign)]
pub trait FillPairingStore: Send + Sync {
    /// The record saved last, if any.
    fn load(&self) -> Option<Vec<u8>>;
    /// Replace the record (after a first pairing or a pairing again).
    fn save(&self, record: Vec<u8>);
}

/// What the app answers to `status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFillStatus {
    Locked,
    Unlocked,
    /// The app is not running, or its bridge is off: "Open OnePass".
    AppClosed,
}

/// How a candidate matched the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFillMatch {
    /// An app entry of the login (`macapp://<bundle id>`), or the page's
    /// exact host.
    ExactHost,
    /// The page's registrable domain (or an associated domain).
    Domain,
}

/// One login the picker offers, without any secret, in the app's order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFillCandidate {
    /// As the bridge names it: pass it back to `fill` unchanged.
    pub item_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub title: String,
    /// The login's identifier (not secret).
    pub subtitle: String,
    pub icon_letter: String,
    pub icon_color: String,
    pub has_password: bool,
    pub has_totp: bool,
    /// `None`: a match on the window title (an app) or a search row.
    pub match_quality: Option<FfiFillMatch>,
    /// The account's label when the app offers several accounts.
    pub account: Option<String>,
}

/// What the helper fills.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFillTarget {
    /// A Mac app. `app_name`: its name, for the remembered entry's label
    /// and the key usage log (the app cuts it to 40 characters; the bundle
    /// id stands in when `None`).
    App {
        bundle_id: String,
        app_name: Option<String>,
    },
    /// A page in a browser without the extension (`url` read from the
    /// accessibility tree at the moment of the fill; the list came from
    /// `list_for_url`). The app checks the login against this page as for
    /// the extension (`origin_mismatch` when the page changed) and asks
    /// Touch ID for the page's host. `app_name`: the browser's name, for
    /// the key usage log (the page's host when `None`). Nothing is
    /// remembered: a page needs no app entry.
    Url {
        url: String,
        app_name: Option<String>,
    },
}

/// The field to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFillField {
    Username,
    Password,
    /// The current one-time code only (never the TOTP secret).
    Totp,
}

/// One value for one fill. The Rust copy is wiped when Swift releases the
/// object. `value()` hands Swift its own copy: Swift copies it into a
/// buffer it overwrites right after the fill, and drops this object at
/// once.
#[derive(uniffi::Object)]
pub struct FfiSecretValue {
    value: Zeroizing<String>,
}

impl std::fmt::Debug for FfiSecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FfiSecretValue(**)")
    }
}

#[uniffi::export]
impl FfiSecretValue {
    /// The value. The returned copy is Swift's to zero.
    pub fn value(&self) -> String {
        self.value.as_str().to_owned()
    }
}

/// A failure inside the client, before it becomes an `OnePassError`.
#[derive(Debug)]
enum Fail {
    /// No socket, refused, or the connection was lost.
    Closed,
    /// The socket is held by someone else than the OnePass app.
    Untrusted,
    /// The app's error code.
    App(String),
    /// An answer the protocol does not allow.
    Protocol,
    /// No answer within the read timeout (or a write that would not go
    /// out): the connection may still be up, the app may still serve the
    /// request. Never retried.
    TimedOut,
}

fn bridge(reason: &str) -> OnePassError {
    OnePassError::Validation {
        field: "bridge".into(),
        reason: reason.into(),
    }
}

impl From<Fail> for OnePassError {
    fn from(f: Fail) -> Self {
        match f {
            Fail::Closed => OnePassError::AppClosed,
            Fail::Untrusted => bridge("untrusted_app"),
            Fail::Protocol => bridge("protocol"),
            Fail::TimedOut => bridge("timeout"),
            Fail::App(code) => match code.as_str() {
                "locked" => OnePassError::Locked,
                "not_found" => OnePassError::NotFound,
                _ => bridge(&code),
            },
        }
    }
}

fn io_fail(e: &io::Error) -> Fail {
    match e.kind() {
        ErrorKind::PermissionDenied => Fail::Untrusted,
        _ => Fail::Closed,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a request lost with its connection may be sent again: reads
/// only, never a fill (the app may have served it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retry {
    Once,
    Never,
}

/// Opens a stream to the app, checked, with the opening frame sent.
type Dial = Box<dyn Fn() -> io::Result<UnixStream> + Send + Sync>;

/// One open session.
struct Live {
    stream: UnixStream,
    ch: Channel,
    next_id: u64,
}

impl Live {
    /// Whether the app closed this connection (EOF or an error waiting):
    /// checked before a request is sent, so a fill never goes out on a
    /// connection already gone.
    fn gone(&self) -> bool {
        if self.stream.set_nonblocking(true).is_err() {
            return true;
        }
        let mut b = [0u8; 1];
        // Reading consumes: fine, since any byte here condemns the
        // connection anyway.
        let gone = match io::Read::read(&mut &self.stream, &mut b) {
            // EOF, or a frame nobody asked for (the protocol has none).
            Ok(_) => true,
            Err(e) => e.kind() != ErrorKind::WouldBlock,
        };
        self.stream.set_nonblocking(false).is_err() || gone
    }

    /// Send one request, read its reply's clear text.
    fn call(&mut self, req: &Request) -> Result<Zeroizing<Vec<u8>>, Fail> {
        let body = serde_json::to_vec(req).map_err(|_| Fail::Protocol)?;
        let env = self.ch.seal(&body).map_err(|_| Fail::Protocol)?;
        send(&mut self.stream, &env)?;
        match recv(&mut self.stream)? {
            Envelope::Msg(m) => self.ch.open(&m).map_err(|_| Fail::Protocol),
            Envelope::Error(e) => Err(Fail::App(e.code)),
            _ => Err(Fail::Protocol),
        }
    }
}

/// A transport failure: a timeout, or a lost connection (EOF, reset,
/// broken pipe and the rest).
fn transport(e: &BridgeError) -> Fail {
    match e {
        BridgeError::Io(ErrorKind::TimedOut | ErrorKind::WouldBlock) => Fail::TimedOut,
        _ => Fail::Closed,
    }
}

fn send(s: &mut UnixStream, env: &Envelope) -> Result<(), Fail> {
    write_frame(s, &wire::to_bytes(env)).map_err(|e| transport(&e))
}

fn recv(s: &mut UnixStream) -> Result<Envelope, Fail> {
    match read_frame(s) {
        Ok(Some(f)) => wire::parse(&f).map_err(|_| Fail::Protocol),
        Ok(None) => Err(Fail::Closed),
        Err(e) => Err(transport(&e)),
    }
}

/// Pair on `s` without a code (the app vouches for the helper by its code
/// signature).
fn pair(s: &mut UnixStream) -> Result<PairingRecord, Fail> {
    let (mut p, mut hello) =
        ExtPairing::start(EXT_NAME, PLATFORM, now()).map_err(|_| Fail::Protocol)?;
    hello.auto = true;
    send(s, &Envelope::PairHello(hello))?;
    let offer = match recv(s)? {
        Envelope::PairOffer(o) => o,
        Envelope::Error(e) => return Err(Fail::App(e.code)),
        _ => return Err(Fail::Protocol),
    };
    let (reveal, _) = p.on_offer(offer).map_err(|_| Fail::Protocol)?;
    send(s, &Envelope::PairReveal(reveal))?;
    match recv(s)? {
        Envelope::PairAuto => {}
        Envelope::Error(e) => return Err(Fail::App(e.code)),
        // `PairSas` too: the helper has no screen to compare a code on.
        _ => return Err(Fail::Protocol),
    }
    let done = match recv(s)? {
        Envelope::PairDone(d) => d,
        Envelope::Error(e) => return Err(Fail::App(e.code)),
        _ => return Err(Fail::Protocol),
    };
    p.on_done(done, now()).map_err(|_| Fail::Protocol)?;
    let (confirm, record) = p.confirm(now()).map_err(|_| Fail::Protocol)?;
    send(s, &Envelope::PairConfirm(confirm))?;
    match recv(s)? {
        Envelope::PairOk => Ok(record),
        Envelope::Error(e) => Err(Fail::App(e.code)),
        _ => Err(Fail::Protocol),
    }
}

/// Open a session on `s` with `record`.
fn open_session(mut s: UnixStream, record: &PairingRecord) -> Result<Live, Fail> {
    let (pending, hello) = session::ext_hello(record).map_err(|_| Fail::Protocol)?;
    send(&mut s, &Envelope::Hello(hello))?;
    let welcome = match recv(&mut s)? {
        Envelope::Welcome(w) => w,
        Envelope::Error(e) => return Err(Fail::App(e.code)),
        _ => return Err(Fail::Protocol),
    };
    let (ch, finish) = pending
        .on_welcome(welcome, now())
        .map_err(|_| Fail::Protocol)?;
    send(&mut s, &Envelope::Finish(finish))?;
    Ok(Live {
        stream: s,
        ch,
        next_id: 1,
    })
}

/// The stored form: version, pairing id, key, creation time, then the two
/// names, each with a 2-byte length (big endian). `None` when a name does
/// not fit its length (never cut).
fn encode(r: &PairingRecord) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(64 + r.ext_name.len() + r.browser.len()));
    out.push(RECORD_V1);
    out.extend_from_slice(&r.pairing_id);
    out.extend_from_slice(&*r.key);
    out.extend_from_slice(&r.created_at.to_be_bytes());
    for name in [&r.ext_name, &r.browser] {
        let len = u16::try_from(name.len()).ok()?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(name.as_bytes());
    }
    Some(out)
}

/// The record of `encode`, or `None` for anything else (then the helper
/// pairs again).
fn decode(b: &[u8]) -> Option<PairingRecord> {
    let (&v, rest) = b.split_first()?;
    if v != RECORD_V1 {
        return None;
    }
    let (id, rest) = rest.split_first_chunk::<16>()?;
    let (key, rest) = rest.split_first_chunk::<32>()?;
    let (at, mut rest) = rest.split_first_chunk::<8>()?;
    let mut names = Vec::with_capacity(2);
    for _ in 0..2 {
        let (len, r) = rest.split_first_chunk::<2>()?;
        let len = usize::from(u16::from_be_bytes(*len));
        if r.len() < len {
            return None;
        }
        let (name, r) = r.split_at(len);
        names.push(std::str::from_utf8(name).ok()?.to_owned());
        rest = r;
    }
    if !rest.is_empty() {
        return None;
    }
    let browser = names.pop()?;
    let ext_name = names.pop()?;
    Some(PairingRecord {
        pairing_id: *id,
        key: Zeroizing::new(*key),
        ext_name,
        browser,
        created_at: u64::from_be_bytes(*at),
    })
}

#[derive(Deserialize)]
struct ErrBody {
    code: String,
}

#[derive(Deserialize)]
#[serde(bound = "T: DeserializeOwned")]
struct Reply<T> {
    id: u64,
    #[serde(default)]
    ok: Option<T>,
    #[serde(default)]
    err: Option<ErrBody>,
}

#[derive(Deserialize)]
struct StatusOk {
    locked: bool,
}

#[derive(Deserialize)]
struct ItemsOk {
    items: Vec<Summary>,
}

#[derive(Deserialize)]
struct LoginOk {
    #[serde(default)]
    username: Option<SecretString>,
    #[serde(default)]
    password: Option<SecretString>,
    #[serde(default)]
    totp: Option<SecretString>,
}

fn candidate(s: Summary) -> FfiFillCandidate {
    FfiFillCandidate {
        item_id: s.item_id,
        vault_id: s.vault_id,
        vault_name: s.vault_name,
        title: s.title,
        subtitle: s.subtitle,
        icon_letter: s.icon_letter,
        icon_color: s.icon_color,
        has_password: s.has_password,
        has_totp: s.has_totp,
        match_quality: s.match_quality.map(|m| match m {
            MatchQuality::ExactHost => FfiFillMatch::ExactHost,
            MatchQuality::Domain | MatchQuality::Associated => FfiFillMatch::Domain,
        }),
        account: s.account,
    }
}

/// The helper's client of the app's bridge.
#[derive(uniffi::Object)]
pub struct DesktopFillClient {
    dial: Dial,
    store: Arc<dyn FillPairingStore>,
    live: Mutex<Option<Live>>,
}

impl std::fmt::Debug for DesktopFillClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DesktopFillClient")
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Connect to `path` and send the opening frame; `check` vets the peer.
fn dial(
    path: &PathBuf,
    check: &dyn Fn(&UnixStream) -> io::Result<()>,
    read_timeout: Duration,
) -> io::Result<UnixStream> {
    let mut s = UnixStream::connect(path)?;
    check(&s)?;
    s.set_read_timeout(Some(read_timeout))?;
    s.set_write_timeout(Some(WRITE_TIMEOUT))?;
    write_frame(&mut s, OPENING).map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
    Ok(s)
}

#[uniffi::export]
impl DesktopFillClient {
    /// The client of the app listening on `socket_path` (`bridge.sock` in
    /// the App Group container). The helper must be signed by a team with
    /// the identifier `<app>.fill`; the socket must be held by `<app>` of
    /// the same team. Pairs at once when `store` holds no record the app
    /// knows. An app that is not running is no error: `status` then says
    /// `AppClosed`, and the next calls reach the app once it runs.
    #[uniffi::constructor]
    pub fn connect(
        socket_path: String,
        store: Arc<dyn FillPairingStore>,
    ) -> Result<Arc<Self>, OnePassError> {
        #[cfg(target_os = "macos")]
        {
            use onepass_relay::rendezvous::{FILL_SUFFIX, is_app, own_identity, peer_identity};

            let (team, me) = own_identity().ok_or_else(|| bridge("unsigned_helper"))?;
            let app = me
                .strip_suffix(FILL_SUFFIX)
                .filter(|a| !a.is_empty())
                .ok_or_else(|| bridge("unsigned_helper"))?
                .to_owned();
            let path = PathBuf::from(socket_path);
            let check = move |s: &UnixStream| match peer_identity(s) {
                Ok(id) if is_app(&id, &team, &app) => Ok(()),
                _ => Err(io::Error::from(ErrorKind::PermissionDenied)),
            };
            Self::start(Box::new(move || dial(&path, &check, READ_TIMEOUT)), store)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (socket_path, store);
            Err(bridge("macos_only"))
        }
    }

    /// Whether the app runs and its vault is unlocked.
    pub fn status(&self) -> Result<FfiFillStatus, OnePassError> {
        match self.call::<StatusOk>(Retry::Once, |id| Request::Status { id }) {
            Ok(s) if s.locked => Ok(FfiFillStatus::Locked),
            Ok(_) => Ok(FfiFillStatus::Unlocked),
            Err(Fail::Closed) => Ok(FfiFillStatus::AppClosed),
            Err(e) => Err(e.into()),
        }
    }

    /// Ask the app to come forward and unlock (Touch ID or the password,
    /// in the app). Answers at once with the state that follows: `Locked`
    /// until the user unlocked.
    pub fn unlock(&self) -> Result<FfiFillStatus, OnePassError> {
        match self.call::<StatusOk>(Retry::Once, |id| Request::Unlock { id, origin: None }) {
            Ok(s) if s.locked => Ok(FfiFillStatus::Locked),
            Ok(_) => Ok(FfiFillStatus::Unlocked),
            Err(Fail::Closed) => Ok(FfiFillStatus::AppClosed),
            Err(e) => Err(e.into()),
        }
    }

    /// The logins for the Mac app `bundle_id`: its app entries first, else
    /// logins whose title has a word of `window_title`.
    pub fn list_for_app(
        &self,
        bundle_id: String,
        window_title: Option<String>,
    ) -> Result<Vec<FfiFillCandidate>, OnePassError> {
        let ok = self.call::<ItemsOk>(Retry::Once, |id| Request::ListForApp {
            id,
            ctx: Ctx::Desktop,
            bundle_id: bundle_id.clone(),
            window_title: window_title.clone(),
        })?;
        Ok(ok.items.into_iter().map(candidate).collect())
    }

    /// The logins for a page shown in a browser without the extension.
    pub fn list_for_url(&self, url: String) -> Result<Vec<FfiFillCandidate>, OnePassError> {
        let ok = self.call::<ItemsOk>(Retry::Once, |id| Request::ListForOrigin {
            id,
            ctx: Ctx::Desktop,
            origin: url.clone(),
        })?;
        Ok(ok.items.into_iter().map(candidate).collect())
    }

    /// The value of `field` of the login `item_id` the user picked, and
    /// nothing else. `remember`: add an app entry for the app to the login
    /// first (an `App` target only: a page is matched by its URL, as in the
    /// browser). The app may confirm with Touch ID (`reprompt` items).
    /// `NotFound` when the login has no such value. Never sent twice: a
    /// fill whose connection is lost is `AppClosed`, one with no answer in
    /// time is `Validation(bridge, timeout)`.
    pub fn fill(
        &self,
        target: FfiFillTarget,
        item_id: String,
        field: FfiFillField,
        remember: bool,
    ) -> Result<Arc<FfiSecretValue>, OnePassError> {
        let wire_field = match field {
            FfiFillField::Username => FillField::Username,
            FfiFillField::Password => FillField::Password,
            FfiFillField::Totp => FillField::Totp,
        };
        let mut ok = match target {
            FfiFillTarget::App {
                bundle_id,
                app_name,
            } => self.call::<LoginOk>(Retry::Never, |id| Request::FillForApp {
                id,
                ctx: Ctx::Desktop,
                item_id: item_id.clone(),
                bundle_id: bundle_id.clone(),
                fields: vec![wire_field],
                remember,
                app_name: app_name.clone(),
            })?,
            // The page's own fill, checked by the app like the extension's.
            FfiFillTarget::Url { url, app_name } => {
                self.call::<LoginOk>(Retry::Never, |id| Request::FillLogin {
                    id,
                    ctx: Ctx::Desktop,
                    agent_request: None,
                    item_id: item_id.clone(),
                    origin: url.clone(),
                    fields: vec![wire_field],
                    app_name: app_name.clone(),
                })?
            }
        };
        let value = match field {
            FfiFillField::Username => ok.username.take(),
            FfiFillField::Password => ok.password.take(),
            FfiFillField::Totp => ok.totp.take(),
        };
        let value = value
            .filter(|v| !v.expose().is_empty())
            .ok_or(OnePassError::NotFound)?;
        Ok(Arc::new(FfiSecretValue { value: value.0 }))
    }
}

impl DesktopFillClient {
    /// Test entry: a client of `socket_path` that checks no code signature
    /// (test binaries are signed ad hoc). Never for a shipped helper.
    #[doc(hidden)]
    pub fn connect_for_tests(
        socket_path: String,
        store: Arc<dyn FillPairingStore>,
    ) -> Result<Arc<Self>, OnePassError> {
        Self::connect_for_tests_with_timeout(socket_path, store, READ_TIMEOUT)
    }

    /// `connect_for_tests` with another read timeout.
    #[doc(hidden)]
    pub fn connect_for_tests_with_timeout(
        socket_path: String,
        store: Arc<dyn FillPairingStore>,
        read_timeout: Duration,
    ) -> Result<Arc<Self>, OnePassError> {
        let path = PathBuf::from(socket_path);
        Self::start(
            Box::new(move || dial(&path, &|_| Ok(()), read_timeout)),
            store,
        )
    }

    fn start(dial: Dial, store: Arc<dyn FillPairingStore>) -> Result<Arc<Self>, OnePassError> {
        let client = DesktopFillClient {
            dial,
            store,
            live: Mutex::new(None),
        };
        {
            let mut live = lock(&client.live);
            match client.open() {
                Ok(l) => *live = Some(l),
                Err(Fail::Closed) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Arc::new(client))
    }

    /// A new session: with the stored record, else (none, unreadable, or
    /// unknown to the app) after pairing again on a new connection.
    fn open(&self) -> Result<Live, Fail> {
        let stored = self
            .store
            .load()
            .map(Zeroizing::new)
            .and_then(|b| decode(&b));
        if let Some(record) = stored {
            let s = (self.dial)().map_err(|e| io_fail(&e))?;
            match open_session(s, &record) {
                Err(Fail::App(code)) if code == "unknown_pairing" || code == "bad_mac" => {}
                other => return other,
            }
        }
        let mut s = (self.dial)().map_err(|e| io_fail(&e))?;
        let record = pair(&mut s)?;
        let bytes = encode(&record).ok_or(Fail::Protocol)?;
        self.store.save(bytes.to_vec());
        open_session(s, &record)
    }

    /// One request and its `ok` payload. With `Retry::Once`, a connection
    /// found closed is opened again and the request sent once more.
    fn call<T: DeserializeOwned>(
        &self,
        retry: Retry,
        req: impl Fn(u64) -> Request,
    ) -> Result<T, Fail> {
        let mut live = lock(&self.live);
        let mut retried = retry == Retry::Never;
        loop {
            if live.as_ref().is_none_or(Live::gone) {
                *live = Some(self.open()?);
            }
            let Some(l) = live.as_mut() else {
                return Err(Fail::Closed);
            };
            let id = l.next_id;
            l.next_id += 1;
            match l.call(&req(id)) {
                Ok(clear) => {
                    let reply: Reply<T> =
                        serde_json::from_slice(&clear).map_err(|_| Fail::Protocol)?;
                    if reply.id != id {
                        *live = None;
                        return Err(Fail::Protocol);
                    }
                    return match (reply.ok, reply.err) {
                        (Some(ok), None) => Ok(ok),
                        (None, Some(e)) => Err(Fail::App(e.code)),
                        _ => Err(Fail::Protocol),
                    };
                }
                Err(Fail::Closed) if !retried => {
                    retried = true;
                    *live = None;
                }
                Err(e) => {
                    *live = None;
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_and_rejects_garbage() {
        let r = PairingRecord {
            pairing_id: [3; 16],
            key: Zeroizing::new([5; 32]),
            ext_name: "OnePass Fill".into(),
            browser: "macOS".into(),
            created_at: 1_700_000_000,
        };
        let b = encode(&r).unwrap();
        let back = decode(&b).unwrap();
        assert_eq!(back.pairing_id, r.pairing_id);
        assert_eq!(*back.key, *r.key);
        assert_eq!(back.ext_name, r.ext_name);
        assert_eq!(back.browser, r.browser);
        assert_eq!(back.created_at, r.created_at);

        assert!(decode(&[]).is_none());
        assert!(decode(&b[..b.len() - 1]).is_none());
        let mut longer = b.to_vec();
        longer.push(0);
        assert!(decode(&longer).is_none());
        let mut v2 = b.to_vec();
        v2[0] = 2;
        assert!(decode(&v2).is_none());
    }

    #[test]
    fn opening_frame_is_the_preamble_of_a_client_with_no_extension() {
        #[cfg(target_os = "macos")]
        assert_eq!(
            OPENING,
            onepass_relay::Preamble::new(None).to_bytes().as_slice()
        );
        assert_eq!(OPENING, br#"{"onepass_relay":1}"#);
    }

    #[test]
    fn app_errors_map_to_the_ffi_error() {
        assert_eq!(
            OnePassError::from(Fail::App("locked".into())),
            OnePassError::Locked
        );
        assert_eq!(
            OnePassError::from(Fail::App("not_found".into())),
            OnePassError::NotFound
        );
        assert_eq!(
            OnePassError::from(Fail::App("not_allowed".into())),
            bridge("not_allowed")
        );
        assert_eq!(OnePassError::from(Fail::Closed), OnePassError::AppClosed);
        assert_eq!(OnePassError::from(Fail::Untrusted), bridge("untrusted_app"));
        assert_eq!(OnePassError::from(Fail::TimedOut), bridge("timeout"));
        assert!(matches!(
            transport(&BridgeError::Io(ErrorKind::WouldBlock)),
            Fail::TimedOut
        ));
        assert!(matches!(
            transport(&BridgeError::Io(ErrorKind::ConnectionReset)),
            Fail::Closed
        ));
    }

    #[test]
    fn a_name_too_long_for_its_length_is_refused_not_cut() {
        let r = PairingRecord {
            pairing_id: [3; 16],
            key: Zeroizing::new([5; 32]),
            ext_name: "x".repeat(usize::from(u16::MAX) + 1),
            browser: "macOS".into(),
            created_at: 1,
        };
        assert!(encode(&r).is_none());
        let fits = PairingRecord {
            ext_name: "x".repeat(usize::from(u16::MAX)),
            ..r
        };
        assert_eq!(
            decode(&encode(&fits).unwrap()).unwrap().ext_name.len(),
            65535
        );
    }
}
