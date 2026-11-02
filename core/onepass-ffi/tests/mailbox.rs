//! The mailbox over the UniFFI surface, called as plain Rust (Task 18): the
//! credential, the creation and enrollment of a mailbox, two devices syncing
//! through `MailboxSync`, a locked round, the clock skew, a pairing that
//! hands over the mailbox, and the wake listener's thread.
//!
//! No network: `Shim` serves the in-memory `FakeMailbox` over loopback TLS
//! (the test CA of `onepass-mailbox`), so the real client signs and checks
//! every request and answer. The shim checks each signature as the edge
//! function does. Synthetic data only. Run with `--features dev-fast-kdf`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use onepass_core::device_keys::{PqDeviceHalf, SoftwarePqHalf};
use onepass_ffi::*;
use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient};
use onepass_mailbox::{Credential, MailboxApi, MailboxError};
use onepass_mailbox_proto::{
    BlobAnnounce, BlobLookup, BlobUrls, Body, ChangesQuery, CommitRequest, CommitResponse,
    CreateMailbox, Enroll, ErrorBody, ErrorCode, ServerConfig, SetPush, content_digest, decode,
    encode, parse_signature_headers, signature_base,
};
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const PREFIX: &str = "/functions/v1/mailbox";
const CA_PEM: &str = include_str!("../../onepass-mailbox/tests/fixtures/ca.pem");
const LEAF_PEM: &str = include_str!("../../onepass-mailbox/tests/fixtures/leaf.pem");
const LEAF_KEY: &str = include_str!("../../onepass-mailbox/tests/fixtures/leaf.key");

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// ---- the mailbox server -------------------------------------------------------

/// `FakeMailbox` behind HTTPS on 127.0.0.1, under the name `localhost`.
/// A request is answered by the fake client of the credential it is signed
/// with; credentials are registered by the test (the fake needs the key).
struct Shim {
    fake: FakeMailbox,
    port: u16,
    clients: Arc<Mutex<Registry>>,
}

impl Shim {
    fn start() -> Shim {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(LEAF_PEM.as_bytes())
                .chain(CertificateDer::pem_slice_iter(CA_PEM.as_bytes()))
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(LEAF_KEY.as_bytes()).unwrap();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fake = FakeMailbox::new();
        fake.set_base_url(&format!("https://localhost:{port}{PREFIX}"));
        let clients = Arc::new(Mutex::new(Registry::default()));
        let c = clients.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (config, c) = (config.clone(), c.clone());
                std::thread::spawn(move || serve(stream, port, config, &c));
            }
        });
        Shim {
            fake,
            port,
            clients,
        }
    }

    fn endpoint(&self) -> FfiMailboxEndpoint {
        FfiMailboxEndpoint {
            base_url: format!("https://localhost:{}{PREFIX}", self.port),
            extra_ca_pem: Some(CA_PEM.into()),
        }
    }

    /// A new credential this server will answer.
    fn credential(&self) -> FfiMailboxCredential {
        let c = mailbox_generate_credential().unwrap();
        let cred = Credential::from_seed(&c.seed).unwrap();
        let client = self.fake.client(Credential::from_seed(&c.seed).unwrap());
        self.clients
            .lock()
            .unwrap()
            .clients
            .insert(cred.id(), (cred, client));
        c
    }
}

/// The credentials the server answers, and the size of every blob uploaded
/// (a download URL names only the hash; the fake checks both).
#[derive(Default)]
struct Registry {
    clients: HashMap<[u8; 16], (Credential, FakeMailboxClient)>,
    sizes: HashMap<[u8; 32], u32>,
}

struct Req {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn serve(
    stream: TcpStream,
    port: u16,
    config: Arc<rustls::ServerConfig>,
    clients: &Mutex<Registry>,
) {
    let conn = rustls::ServerConnection::new(config).unwrap();
    let mut reader = BufReader::new(rustls::StreamOwned::new(conn, stream));
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        if reader.read_line(&mut l).unwrap_or(0) == 0 {
            return;
        }
        let l = l.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let (n, v) = l.split_once(':').unwrap();
        headers.push((n.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let len: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .map_or(0, |(_, v)| v.parse().unwrap());
    let mut body = vec![0; len];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let target = path.strip_prefix(PREFIX).unwrap_or(&path);
    let req = Req {
        method,
        target: target.to_string(),
        headers,
        body,
    };
    let (status, body) = match answer(&req, port, clients) {
        Ok(ok) => ok,
        // The fake could not be reached: the connection drops, unanswered.
        Err(MailboxError::Offline) => return,
        Err(e) => error(&e),
    };
    let mut out = format!(
        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    if !body.is_empty() {
        out.push_str(&format!(
            "content-type: {}\r\n",
            onepass_mailbox_proto::CONTENT_TYPE
        ));
    }
    out.push_str("\r\n");
    let tls = reader.get_mut();
    let _ = tls.write_all(out.as_bytes());
    let _ = tls.write_all(&body);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// The error body of `e`, with the status of its code (spec 4.6).
fn error(e: &MailboxError) -> (u16, Vec<u8>) {
    let (code, after) = match e {
        MailboxError::Stale => (ErrorCode::StaleRequest, None),
        MailboxError::CursorExpired => (ErrorCode::CursorExpired, None),
        MailboxError::TooLarge => (ErrorCode::TooLarge, None),
        MailboxError::Forbidden => (ErrorCode::Forbidden, None),
        MailboxError::Retry { after } => (ErrorCode::Retry, *after),
        MailboxError::Server(c) => (*c, None),
        _ => (ErrorCode::Malformed, None),
    };
    let status = match code {
        ErrorCode::Malformed => 400,
        ErrorCode::BadSignature | ErrorCode::StaleRequest | ErrorCode::Replay => 401,
        ErrorCode::UnknownCredential
        | ErrorCode::RevokedCredential
        | ErrorCode::Frozen
        | ErrorCode::Forbidden => 403,
        ErrorCode::NotFound | ErrorCode::NoRoute | ErrorCode::Absent => 404,
        ErrorCode::CursorExpired => 410,
        ErrorCode::TooLarge => 413,
        ErrorCode::Quota => 422,
        ErrorCode::RateLimited => 429,
        ErrorCode::Retry => 503,
    };
    (
        status,
        encode(&ErrorBody {
            code,
            retry_after: after,
        }),
    )
}

/// Checks the signature (spec 4.7) and returns the key id.
fn signer(req: &Req, clients: &Registry) -> Result<[u8; 16], MailboxError> {
    let bad = MailboxError::Server(ErrorCode::BadSignature);
    let parsed = parse_signature_headers(
        req.header("signature-input").ok_or(bad.clone())?,
        req.header("signature").ok_or(bad.clone())?,
    )
    .map_err(|_| bad.clone())?;
    let digest = req.header("content-digest").ok_or(bad.clone())?;
    if digest != content_digest(&req.body) {
        return Err(bad);
    }
    let base = signature_base(&req.method, &req.target, digest, &parsed.params)
        .map_err(|_| bad.clone())?;
    let (cred, _) = clients
        .clients
        .get(&parsed.params.keyid)
        .ok_or(MailboxError::Server(ErrorCode::UnknownCredential))?;
    UnparsedPublicKey::new(&ED25519, cred.public_key().as_bytes())
        .verify(&base, &parsed.sig)
        .map_err(|_| bad)?;
    Ok(parsed.params.keyid)
}

fn hex16(s: &str) -> Result<[u8; 16], MailboxError> {
    let bad = MailboxError::Server(ErrorCode::NoRoute);
    if s.len() != 32 {
        return Err(bad);
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad.clone())?;
    }
    Ok(out)
}

fn ok<M: onepass_mailbox_proto::Message>(m: &M) -> (u16, Vec<u8>) {
    (200, encode(m))
}

fn body<M: onepass_mailbox_proto::Message>(req: &Req) -> Result<M, MailboxError> {
    decode(&req.body).map_err(|_| MailboxError::Server(ErrorCode::Malformed))
}

/// A Storage URL of this server for blob `h`, on behalf of credential `id`
/// (Storage itself is not signed: the fake client of `id` does the work).
fn storage(port: u16, op: &str, id: [u8; 16], h: &[u8; 32]) -> String {
    format!(
        "https://localhost:{port}/storage/{op}/{}/{}",
        onepass_mailbox_proto::hex(&id),
        onepass_mailbox_proto::hex(h)
    )
}

/// `PUT /storage/up/{id}/{sha}` and `GET /storage/get/{id}/{sha}`.
fn answer_storage(req: &Req, clients: &Mutex<Registry>) -> Result<(u16, Vec<u8>), MailboxError> {
    let segs: Vec<&str> = req.target.trim_start_matches('/').split('/').collect();
    let registry = clients.lock().unwrap();
    let (op, id, sha) = match segs.as_slice() {
        ["storage", op, id, sha] => (*op, hex16(id)?, *sha),
        _ => return Err(MailboxError::Server(ErrorCode::NotFound)),
    };
    let (_, client) = registry
        .clients
        .get(&id)
        .ok_or(MailboxError::Server(ErrorCode::NotFound))?;
    match (req.method.as_str(), op) {
        ("PUT", "up") => {
            client.upload_blobs(&[&req.body])?;
            Ok((200, vec![]))
        }
        ("GET", "get") => {
            let mut h = [0u8; 32];
            for (i, o) in h.iter_mut().enumerate() {
                *o = u8::from_str_radix(&sha[2 * i..2 * i + 2], 16)
                    .map_err(|_| MailboxError::Server(ErrorCode::NotFound))?;
            }
            let size = *registry
                .sizes
                .get(&h)
                .ok_or(MailboxError::Server(ErrorCode::NotFound))?;
            let blob = Body::Blob { sha256: h, size };
            Ok((200, client.fetch_body(&blob)?))
        }
        _ => Err(MailboxError::Server(ErrorCode::NotFound)),
    }
}

fn answer(req: &Req, port: u16, clients: &Mutex<Registry>) -> Result<(u16, Vec<u8>), MailboxError> {
    if req.target.starts_with("/storage/") {
        return answer_storage(req, clients);
    }
    if req.method == "GET" && req.target == "/v1/config" {
        return Ok(ok(&ServerConfig {
            realtime_url: "wss://localhost:1/realtime/v1".into(),
            publishable_key: "pk-test".into(),
            open_signup: true,
        }));
    }
    let mut registry = clients.lock().unwrap();
    let id = signer(req, &registry)?;
    let Registry { clients, sizes } = &mut *registry;
    let (_, client) = clients.get_mut(&id).unwrap();
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (req.method.as_str(), segs.as_slice()) {
        ("POST", ["v1", "mailboxes"]) => {
            let r: CreateMailbox = body(req)?;
            Ok(ok(&client.create(r.invite.as_deref(), &r.label)?))
        }
        ("POST", ["v1", "mailboxes", _, "credentials"]) => {
            let r: Enroll = body(req)?;
            client.enroll(&r.ticket, &r.label)?;
            Ok((204, vec![]))
        }
        (method, ["v1", "mailboxes", m, rest @ ..]) => {
            client.open(hex16(m)?);
            match (method, rest) {
                ("GET", []) => Ok(ok(&client.info()?)),
                ("GET", ["changes"]) => {
                    let q = ChangesQuery::parse(query)
                        .map_err(|_| MailboxError::Server(ErrorCode::Malformed))?;
                    Ok(ok(&client.changes(q.after, q.limit, q.full)?))
                }
                ("POST", ["commit"]) => {
                    let r: CommitRequest = body(req)?;
                    let answer = client.commit(r.ops)?;
                    let status = match answer {
                        CommitResponse::Applied { .. } => 200,
                        CommitResponse::Conflict { .. } => 409,
                    };
                    Ok((status, encode(&answer)))
                }
                ("GET", ["records", kind, rid]) => {
                    let kind: u8 = kind
                        .parse()
                        .map_err(|_| MailboxError::Server(ErrorCode::NoRoute))?;
                    match client.record(kind, hex16(rid)?)? {
                        Some(r) => Ok(ok(&r)),
                        None => Err(MailboxError::Server(ErrorCode::Absent)),
                    }
                }
                ("PUT", ["push"]) => {
                    let r: SetPush = body(req)?;
                    client.set_push(r.kind, &r.token)?;
                    Ok((204, vec![]))
                }
                ("DELETE", ["credentials", c]) => {
                    client.revoke(hex16(c)?)?;
                    Ok((204, vec![]))
                }
                ("POST", ["blobs", "uploads"]) => {
                    let r: BlobAnnounce = body(req)?;
                    sizes.extend(r.blobs.iter().copied());
                    let urls = r
                        .blobs
                        .iter()
                        .map(|(h, _)| (*h, Some(storage(port, "up", id, h))))
                        .collect();
                    Ok(ok(&BlobUrls { urls }))
                }
                ("POST", ["blobs", "downloads"]) => {
                    let r: BlobLookup = body(req)?;
                    let urls = r
                        .blobs
                        .iter()
                        .map(|h| (*h, Some(storage(port, "get", id, h))))
                        .collect();
                    Ok(ok(&BlobUrls { urls }))
                }
                _ => Err(MailboxError::Server(ErrorCode::NoRoute)),
            }
        }
        _ => Err(MailboxError::Server(ErrorCode::NoRoute)),
    }
}

// ---- devices ----------------------------------------------------------------

fn db_path(dir: &Path) -> String {
    dir.join("onepass.db").to_string_lossy().into_owned()
}

fn login(session: &Session, title: &str) -> FfiItem {
    let vault = session.vaults().unwrap()[0].id.clone();
    let mut item = session
        .new_item(vault, FfiItemType::Login, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "username" {
            f.value = FfiFieldValue::Text {
                value: "camille@exemple.fr".into(),
            };
        }
    }
    item
}

fn titles(session: &Session) -> Vec<String> {
    let mut t: Vec<String> = session
        .item_summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    t.sort();
    t
}

/// Rounds until one ends `Idle` with nothing left to run.
fn settle(sync: &MailboxSync, session: Option<Arc<Session>>) -> FfiRoundReport {
    let mut changed = false;
    let mut seen = Vec::new();
    for _ in 0..12 {
        let mut r = sync.run_round(session.clone(), now());
        changed |= r.changed;
        if r.status == FfiRoundStatus::Idle && !r.rerun {
            r.changed = changed;
            return r;
        }
        seen.push(r);
    }
    panic!("no idle round: {seen:?}");
}

fn mailbox_backend(home: &FfiMailboxHome) -> FfiSyncBackend {
    FfiSyncBackend::Mailbox {
        base_url: home.base_url.clone(),
        mailbox_id: home.mailbox_id.clone(),
    }
}

/// The first device: an account, a mailbox it created, the account's home
/// set to it, one login saved and synced.
struct First {
    _dir: TempDir,
    path: String,
    session: Arc<Session>,
    secret_key: String,
    home: FfiMailboxHome,
    sync: Arc<MailboxSync>,
}

fn first_device(shim: &Shim, session_and_key: (Arc<Session>, String), dir: TempDir) -> First {
    let (session, secret_key) = session_and_key;
    let path = db_path(dir.path());
    let cred = shim.credential();
    let home = mailbox_create(shim.endpoint(), cred.seed.clone(), None).unwrap();
    assert_eq!(home.base_url, shim.endpoint().base_url);
    let set = session.set_sync_home(mailbox_backend(&home)).unwrap();
    assert_eq!(set.seq, 1);
    assert_eq!(session.sync_home().unwrap(), Some(set));
    session.save_item(login(&session, "Messagerie")).unwrap();
    let sync = MailboxSync::open(
        path.clone(),
        shim.endpoint(),
        home.mailbox_id.clone(),
        cred.seed,
    )
    .unwrap();
    settle(&sync, Some(session.clone()));
    First {
        _dir: dir,
        path,
        session,
        secret_key,
        home,
        sync,
    }
}

fn legacy_first(shim: &Shim) -> First {
    let dir = TempDir::new().unwrap();
    let created = create_account_with_kdf(db_path(dir.path()), PASSWORD.into(), FAST).unwrap();
    first_device(shim, (created.session, created.secret_key), dir)
}

// ---- tests ------------------------------------------------------------------

#[test]
fn credential_is_fresh_and_named_by_its_key() {
    let a = mailbox_generate_credential().unwrap();
    let b = mailbox_generate_credential().unwrap();
    assert_ne!(a.seed, b.seed);
    assert_eq!(a.public_key.len(), 32);
    assert_eq!(a.id.len(), 32);
    let c = Credential::from_seed(&a.seed).unwrap();
    assert_eq!(
        c.public_key().as_bytes().as_slice(),
        a.public_key.as_slice()
    );
}

#[test]
fn two_devices_sync_through_the_mailbox() {
    let shim = Shim::start();
    let a = legacy_first(&shim);

    // B joins the mailbox with a ticket A issues for its credential.
    let cred_b = shim.credential();
    let ticket = a
        .sync
        .issue_enroll_ticket(cred_b.public_key.clone(), now())
        .unwrap();
    let home_b = mailbox_enroll(cred_b.seed.clone(), ticket, Some(CA_PEM.into())).unwrap();
    assert_eq!(home_b, a.home);

    // Locked, B fetches the account: no rebase, nothing refused.
    let dir_b = TempDir::new().unwrap();
    let path_b = db_path(dir_b.path());
    let sync_b = MailboxSync::open(
        path_b.clone(),
        shim.endpoint(),
        home_b.mailbox_id.clone(),
        cred_b.seed,
    )
    .unwrap();
    let locked = settle(&sync_b, None);
    assert!(locked.changed);
    assert!(locked.rebased.is_empty());
    let b = unlock_with_password(path_b, PASSWORD.into(), a.secret_key.clone())
        .unwrap()
        .session;
    settle(&sync_b, Some(b.clone()));
    assert_eq!(titles(&b), ["Messagerie"]);
    assert_eq!(b.sync_home().unwrap(), a.session.sync_home().unwrap());

    // An edit on A reaches B.
    a.session.save_item(login(&a.session, "Banque")).unwrap();
    settle(&a.sync, Some(a.session.clone()));
    let r = settle(&sync_b, Some(b.clone()));
    assert!(r.changed);
    assert_eq!(titles(&b), ["Banque", "Messagerie"]);

    // A locked session is the same as none.
    b.lock();
    assert_eq!(settle(&sync_b, Some(b)).status, FfiRoundStatus::Idle);
    let _ = &a.path;
}

#[test]
fn clock_skew_reaches_the_app() {
    let shim = Shim::start();
    let a = legacy_first(&shim);
    shim.fake.faults().fail_next(MailboxError::Stale);
    let r = a.sync.run_round(Some(a.session.clone()), now());
    assert_eq!(r.status, FfiRoundStatus::ClockSkew);
    assert!(r.retry_after_seconds.is_some());
    shim.fake.faults().fail_next(MailboxError::Stale);
    assert_eq!(a.sync.wake_info(), Err(OnePassError::ClockSkew));
    let info = a.sync.wake_info().unwrap();
    assert_eq!(info.topic.len(), 32);
    assert_eq!(info.publishable_key, "pk-test");
    assert_eq!(
        settle(&a.sync, Some(a.session.clone())).status,
        FfiRoundStatus::Idle
    );
}

#[test]
fn an_unknown_server_is_unavailable_not_a_crash() {
    let cred = mailbox_generate_credential().unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let endpoint = FfiMailboxEndpoint {
        base_url: format!("https://localhost:{port}{PREFIX}"),
        extra_ca_pem: Some(CA_PEM.into()),
    };
    assert!(matches!(
        mailbox_create(endpoint, cred.seed, None),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    assert!(matches!(
        mailbox_enroll(vec![1; 32], vec![1, 2, 3], None),
        Err(OnePassError::InvalidInput { .. })
    ));
}

#[test]
fn sync_home_refuses_a_plain_http_mailbox() {
    let dir = TempDir::new().unwrap();
    let created = create_account_with_kdf(db_path(dir.path()), PASSWORD.into(), FAST).unwrap();
    assert_eq!(created.session.sync_home().unwrap(), None);
    let bad = FfiSyncBackend::Mailbox {
        base_url: "http://localhost/functions/v1/mailbox".into(),
        mailbox_id: "00".repeat(16),
    };
    assert!(created.session.set_sync_home(bad).is_err());
    let cloud = created
        .session
        .set_sync_home(FfiSyncBackend::CloudKit)
        .unwrap();
    assert_eq!(cloud.backend, FfiSyncBackend::CloudKit);
}

// ---- pairing --------------------------------------------------------------------

struct Half(SoftwarePqHalf);

impl FfiPqDeviceHalf for Half {
    fn mldsa_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mldsa_public().map_err(|_| OnePassError::Crypto)
    }

    fn mlkem_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mlkem_public().map_err(|_| OnePassError::Crypto)
    }

    fn mldsa_sign(&self, message: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        self.0
            .mldsa_sign(&message)
            .map_err(|_| OnePassError::Crypto)
    }

    fn mlkem_decapsulate(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        Ok(self
            .0
            .mlkem_decapsulate(&ciphertext)
            .map_err(|_| OnePassError::Crypto)?
            .to_vec())
    }
}

struct Keys {
    classical: Vec<u8>,
    pq: Vec<u8>,
}

impl Keys {
    fn new() -> Keys {
        Keys {
            classical: generate_classical_device_keys().unwrap(),
            pq: SoftwarePqHalf::generate().unwrap().to_bytes().to_vec(),
        }
    }

    fn half(&self) -> Arc<dyn FfiPqDeviceHalf> {
        Arc::new(Half(SoftwarePqHalf::from_bytes(&self.pq).unwrap()))
    }
}

#[test]
fn pairing_hands_over_the_mailbox_with_a_ticket() {
    let shim = Shim::start();
    let dir = TempDir::new().unwrap();
    let keys_a = Keys::new();
    let created = create_account_v2(
        db_path(dir.path()),
        PASSWORD.into(),
        Some(FAST),
        keys_a.classical.clone(),
        keys_a.half(),
        "Mac de Camille".into(),
        FfiDeviceKind::Mac,
        FfiDeviceMode::Personal,
    )
    .unwrap();
    let a = first_device(&shim, (created.session, created.secret_key), dir);

    // The newcomer sends its credential key inside the SAS channel.
    let cred_b = shim.credential();
    let keys_b = Keys::new();
    let n = PairingNewcomer::new(
        "Pixel de Camille".into(),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
        now(),
        Some(cred_b.public_key.clone()),
    )
    .unwrap();
    let ap = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    n.on_key_exchange(ap.key_exchange(), now()).unwrap();
    let f = n
        .confirm_with_key(keys_b.classical.clone(), keys_b.half())
        .unwrap();
    assert_eq!(ap.on_frame(f).unwrap(), FfiPairingMessage::Confirmed);
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
            Some(a.sync.clone()),
        )
        .unwrap();
    assert!(matches!(
        n.open(frame).unwrap(),
        FfiPairingMessage::FullGrant { .. }
    ));

    // The grant names the account's home and a ticket for this credential.
    let enrollment = n.mailbox_enrollment().unwrap().expect("a mailbox to join");
    assert_eq!(enrollment.home, a.session.sync_home().unwrap().unwrap());
    assert_eq!(n.grant_sync_home(), Some(enrollment.home.clone()));
    let home_b =
        mailbox_enroll(cred_b.seed.clone(), enrollment.ticket, Some(CA_PEM.into())).unwrap();
    assert_eq!(mailbox_backend(&home_b), enrollment.home.backend);

    // B imports the snapshot and syncs through the mailbox.
    let dir_b = TempDir::new().unwrap();
    let path_b = db_path(dir_b.path());
    let b = n
        .import_snapshot_v2(
            path_b.clone(),
            PASSWORD.into(),
            keys_b.classical.clone(),
            keys_b.half(),
        )
        .unwrap()
        .session;
    let ack = n
        .seal_key_ack(keys_b.classical.clone(), keys_b.half())
        .unwrap();
    assert_eq!(ap.on_frame(ack).unwrap(), FfiPairingMessage::Ack);
    ap.introduce(a.session.clone(), keys_a.classical.clone(), keys_a.half())
        .unwrap();
    let sync_b =
        MailboxSync::open(path_b, shim.endpoint(), home_b.mailbox_id, cred_b.seed).unwrap();
    settle(&a.sync, Some(a.session.clone()));
    settle(&sync_b, Some(b.clone()));
    assert_eq!(titles(&b), ["Messagerie"]);
    b.save_item(login(&b, "Train")).unwrap();
    settle(&sync_b, Some(b.clone()));
    settle(&a.sync, Some(a.session.clone()));
    assert_eq!(titles(&a.session), ["Messagerie", "Train"]);
}

#[test]
fn approver_without_a_mailbox_grants_no_ticket() {
    let shim = Shim::start();
    let dir = TempDir::new().unwrap();
    let keys_a = Keys::new();
    let created = create_account_v2(
        db_path(dir.path()),
        PASSWORD.into(),
        Some(FAST),
        keys_a.classical.clone(),
        keys_a.half(),
        "Mac de Camille".into(),
        FfiDeviceKind::Mac,
        FfiDeviceMode::Personal,
    )
    .unwrap();
    let a = first_device(&shim, (created.session, created.secret_key), dir);
    let keys_b = Keys::new();
    let n = PairingNewcomer::new(
        "Pixel de Camille".into(),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
        now(),
        Some(vec![7; 32]),
    )
    .unwrap();
    let ap = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    n.on_key_exchange(ap.key_exchange(), now()).unwrap();
    let f = n
        .confirm_with_key(keys_b.classical.clone(), keys_b.half())
        .unwrap();
    ap.on_frame(f).unwrap();
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
            None,
        )
        .unwrap();
    n.open(frame).unwrap();
    assert_eq!(n.mailbox_enrollment().unwrap(), None);
    assert_eq!(n.grant_sync_home(), a.session.sync_home().unwrap());
    assert!(
        PairingNewcomer::new(
            "x".into(),
            FfiDeviceKind::Phone,
            FfiDeviceMode::Personal,
            now(),
            Some(vec![7; 31]),
        )
        .is_err()
    );
}

// ---- the wake listener ------------------------------------------------------

/// Counts wakes; `dropped` is set once the listener let go of it (its
/// thread ended).
struct Observer {
    wakes: AtomicUsize,
    dropped: Arc<AtomicBool>,
}

impl FfiWakeObserver for Observer {
    fn wake(&self) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn wake_listener_stop_ends_its_thread() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let dropped = Arc::new(AtomicBool::new(false));
    let observer: Arc<dyn FfiWakeObserver> = Arc::new(Observer {
        wakes: AtomicUsize::new(0),
        dropped: dropped.clone(),
    });
    let info = FfiWakeInfo {
        realtime_url: format!("wss://localhost:{port}/realtime/v1"),
        publishable_key: "pk-test".into(),
        topic: "ab".repeat(16),
    };
    let handle = start_wake_listener(info.clone(), observer).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!dropped.load(Ordering::SeqCst), "listener runs until stop");
    handle.stop();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !dropped.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "the listener thread never ended");
        std::thread::sleep(Duration::from_millis(50));
    }
    handle.stop();

    let bad = FfiWakeInfo {
        topic: "zz".into(),
        ..info
    };
    let o: Arc<dyn FfiWakeObserver> = Arc::new(Observer {
        wakes: AtomicUsize::new(0),
        dropped: Arc::new(AtomicBool::new(false)),
    });
    assert!(start_wake_listener(bad, o).is_err());
}

#[test]
fn rendezvous_checks_its_session_and_url() {
    let base = "https://localhost:1/functions/v1/mailbox".to_string();
    assert!(
        RendezvousTransport::new(base.clone(), "ab".into(), FfiRdvRole::Newcomer, None).is_err()
    );
    assert!(
        RendezvousTransport::new(
            "ftp://x".into(),
            "ab".repeat(16),
            FfiRdvRole::Approver,
            None
        )
        .is_err()
    );
    let t = RendezvousTransport::new(base, "ab".repeat(16), FfiRdvRole::Newcomer, None).unwrap();
    t.close();
    assert!(t.send(vec![1]).is_err());
}
