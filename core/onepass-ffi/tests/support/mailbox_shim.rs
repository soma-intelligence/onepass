// The mailbox server of the FFI tests, included (`include!`) by
// `mailbox.rs` and `x1b.rs`: `FakeMailbox` over loopback TLS, the devices
// and the software device keys they use.

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
    CreateMailbox, Enroll, ErrorBody, GrantCredential, LocateRequest, Located, SetLocator, ErrorCode, ServerConfig, SetPush, content_digest, decode,
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
const CA_PEM: &str = include_str!("../../../onepass-mailbox/tests/fixtures/ca.pem");
const LEAF_PEM: &str = include_str!("../../../onepass-mailbox/tests/fixtures/leaf.pem");
const LEAF_KEY: &str = include_str!("../../../onepass-mailbox/tests/fixtures/leaf.key");

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
        let clients = Arc::new(Mutex::new(Registry {
            fake: Some(fake.clone()),
            ..Registry::default()
        }));
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
        self.register(&c);
        c
    }

    /// Answer requests signed by `c` (a derived recovery credential).
    fn register(&self, c: &FfiMailboxCredential) {
        let cred = Credential::from_seed(&c.seed).unwrap();
        let client = self.fake.client(Credential::from_seed(&c.seed).unwrap());
        self.clients
            .lock()
            .unwrap()
            .clients
            .insert(cred.id(), (cred, client));
    }
}

/// The credentials the server answers, and the size of every blob uploaded
/// (a download URL names only the hash; the fake checks both).
#[derive(Default)]
struct Registry {
    fake: Option<FakeMailbox>,
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
        let ct = if req.target.starts_with("/v1/drops/") {
            "application/octet-stream"
        } else {
            onepass_mailbox_proto::CONTENT_TYPE
        };
        out.push_str(&format!("content-type: {ct}\r\n"));
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
    if req.target.starts_with("/v1/drops/") {
        // Invite drops (sharing spec 13.9): unsigned, the id is the key.
        let fake = registry.fake.as_ref().unwrap();
        let segs: Vec<&str> = req.target.trim_start_matches('/').split('/').collect();
        return match (req.method.as_str(), segs.as_slice()) {
            ("PUT", ["v1", "drops", id, slot]) => {
                let slot: u8 = slot.parse().map_err(|_| MailboxError::Server(ErrorCode::Malformed))?;
                match fake.drop_put(hex16(id)?, slot, &req.body) {
                    Ok(()) => Ok((204, vec![])),
                    Err(MailboxError::Conflict) => Ok((409, vec![])),
                    Err(e) => Err(e),
                }
            }
            ("GET", ["v1", "drops", id, slot]) => {
                let slot: u8 = slot.parse().map_err(|_| MailboxError::Server(ErrorCode::Malformed))?;
                Ok(match fake.drop_get(hex16(id)?, slot)? {
                    Some(b) => (200, b),
                    None => (204, vec![]),
                })
            }
            ("DELETE", ["v1", "drops", id]) => {
                fake.drop_delete(hex16(id)?)?;
                Ok((204, vec![]))
            }
            _ => Err(MailboxError::Server(ErrorCode::NoRoute)),
        };
    }
    if req.method == "POST" && req.target == "/v1/locate" {
        let r: LocateRequest = body(req)?;
        let fake = registry.fake.as_ref().unwrap();
        // None is a 404, as the edge function answers it.
        let mailbox_ids = fake.locate(r.locator)?;
        if mailbox_ids.is_empty() {
            return Err(MailboxError::Server(ErrorCode::NotFound));
        }
        return Ok(ok(&Located { mailbox_ids }));
    }
    let id = signer(req, &registry)?;
    let Registry { clients, sizes, .. } = &mut *registry;
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
                ("DELETE", []) => {
                    client.abandon()?;
                    Ok((204, vec![]))
                }
                ("POST", ["grants"]) => {
                    let r: GrantCredential = body(req)?;
                    client.grant(r.public_key, r.role, r.put_kinds, &r.label)?;
                    Ok((204, vec![]))
                }
                ("PUT", ["locator"]) => {
                    let r: SetLocator = body(req)?;
                    client.set_locator(r.locator)?;
                    Ok((204, vec![]))
                }
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
