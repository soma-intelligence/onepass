//! Tests only (fast-KDF test framework): `FakeMailbox` served over loopback
//! TLS (the test CA of `onepass-mailbox`), so the Swift tests drive real zone
//! rounds, contact drops and recoveries between two accounts in one process.
//! Never built into a shipped framework (`dev-fast-kdf` is refused outside
//! debug builds, and `onepass-mailbox/testing` with it).
//!
//! The same server as `tests/support/mailbox_shim.rs`, without the test's
//! credential registration: every credential is one the fake already holds
//! or one a mailbox creation carries.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient};
use onepass_mailbox::{CredentialKey, MailboxApi, MailboxError};
use onepass_mailbox_proto::{
    BlobAnnounce, BlobLookup, BlobUrls, Body, ChangesQuery, CommitRequest, CommitResponse,
    CreateChild, CreateMailbox, Enroll, ErrorBody, ErrorCode, GrantCredential, LocateRequest,
    Located, ServerConfig, SetCredentialRole, SetLocator, SetPush, content_digest, decode, encode,
    parse_signature_headers, signature_base,
};

use crate::error::OnePassError;
use crate::mailbox::FfiMailboxEndpoint;

const PREFIX: &str = "/functions/v1/mailbox";
const CA_PEM: &str = include_str!("../../onepass-mailbox/tests/fixtures/ca.pem");
const LEAF_PEM: &str = include_str!("../../onepass-mailbox/tests/fixtures/leaf.pem");
const LEAF_KEY: &str = include_str!("../../onepass-mailbox/tests/fixtures/leaf.key");

/// Starts a mailbox server of its own on 127.0.0.1 (name `localhost`) and
/// returns its endpoint. It runs until the process ends.
#[uniffi::export]
pub fn test_mailbox_start() -> Result<FfiMailboxEndpoint, OnePassError> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let fail = |_| OnePassError::Store;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(LEAF_PEM.as_bytes())
        .chain(CertificateDer::pem_slice_iter(CA_PEM.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| OnePassError::Store)?;
    let key =
        PrivateKeyDer::from_pem_slice(LEAF_KEY.as_bytes()).map_err(|_| OnePassError::Store)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| OnePassError::Store)?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|_| OnePassError::Store)?,
    );
    let listener = TcpListener::bind("127.0.0.1:0").map_err(fail)?;
    let port = listener.local_addr().map_err(fail)?.port();
    let fake = FakeMailbox::new();
    fake.set_base_url(&format!("https://localhost:{port}{PREFIX}"));
    let clients = Arc::new(Mutex::new(Registry {
        fake: Some(fake),
        ..Registry::default()
    }));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (config, c) = (config.clone(), clients.clone());
            std::thread::spawn(move || serve(stream, port, config, &c));
        }
    });
    Ok(FfiMailboxEndpoint {
        base_url: format!("https://localhost:{port}{PREFIX}"),
        extra_ca_pem: Some(CA_PEM.into()),
    })
}

/// The credentials the server answers, and the size of every blob uploaded
/// (a download URL names only the hash; the fake checks both).
#[derive(Default)]
struct Registry {
    fake: Option<FakeMailbox>,
    /// By credential id: its public key and the fake client acting for it.
    clients: HashMap<[u8; 16], (CredentialKey, FakeMailboxClient)>,
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

/// Checks the signature (spec 4.7) and returns the key id. A credential
/// the test did not register is answered when its key is known: the one a
/// mailbox creation carries, or one the fake holds (created, granted or
/// enrolled earlier), as the edge function reads it from its table. Zone
/// credentials are made inside the core, so the test never sees them.
fn signer(req: &Req, clients: &mut Registry) -> Result<[u8; 16], MailboxError> {
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
    let keyid = parsed.params.keyid;
    if !clients.clients.contains_key(&keyid) {
        let fake = clients.fake.clone().unwrap();
        let created = (req.method == "POST" && req.target == "/v1/mailboxes")
            .then(|| decode::<CreateMailbox>(&req.body).ok())
            .flatten()
            .map(|c| CredentialKey::from_bytes(c.public_key));
        let key = fake
            .credential_key(keyid)
            .or(created)
            .filter(|k| k.id() == keyid)
            .ok_or(MailboxError::Server(ErrorCode::UnknownCredential))?;
        clients
            .clients
            .insert(keyid, (key, fake.client_for_key(key)));
    }
    let (key, _) = &clients.clients[&keyid];
    UnparsedPublicKey::new(&ED25519, key.as_bytes())
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
                let slot: u8 = slot
                    .parse()
                    .map_err(|_| MailboxError::Server(ErrorCode::Malformed))?;
                match fake.drop_put(hex16(id)?, slot, &req.body) {
                    Ok(()) => Ok((204, vec![])),
                    Err(MailboxError::Conflict) => Ok((409, vec![])),
                    Err(e) => Err(e),
                }
            }
            ("GET", ["v1", "drops", id, slot]) => {
                let slot: u8 = slot
                    .parse()
                    .map_err(|_| MailboxError::Server(ErrorCode::Malformed))?;
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
    let id = signer(req, &mut registry)?;
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
                ("POST", ["children"]) => {
                    let r: CreateChild = body(req)?;
                    Ok(ok(&client.create_child(
                        r.kind,
                        r.owner_public_key,
                        &r.label,
                    )?))
                }
                ("PUT", ["credentials", c, "role"]) => {
                    let r: SetCredentialRole = body(req)?;
                    client.set_role(hex16(c)?, r.role, r.put_kinds)?;
                    Ok((204, vec![]))
                }
                ("PUT", ["push-targets", tag]) => {
                    let r: SetPush = body(req)?;
                    client.set_push_target(hex16(tag)?, r.kind, &r.token)?;
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
