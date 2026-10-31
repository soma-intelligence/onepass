//! The blocking mailbox client against a small fake HTTP server on a thread
//! (std only). The server checks every signed request with the proto
//! functions and aws-lc-rs, the way the edge function does.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use onepass_mailbox::{
    ChangeFeed, Credential, CredentialKey, Endpoint, MailboxClient, MailboxError, RdvRole,
    Rendezvous, tls_client_config,
};
use onepass_mailbox_proto::{
    BlobAnnounce, BlobLookup, BlobUrls, Body, COMMIT_BODY_MAX, ChangesPage, ChangesQuery, CommitOp,
    CommitRequest, CommitResponse, ConflictEntry, CreateMailbox, Enroll, ErrorBody, ErrorCode,
    INLINE_MAX, Limits, MailboxCreated, MailboxInfo, Op, PushKind, RECORD_MAX, ServerConfig,
    ServerRecord, SetPush, Usage, blob_sha256, check_skew, content_digest, credential_id, decode,
    encode, hex, parse_signature_headers, signature_base, ticket_signed_bytes,
};

const PREFIX: &str = "/functions/v1/mailbox";
const MAILBOX: [u8; 16] = [9; 16];

// ------------------------------------------------------------ fake server

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
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

    /// The `@onepass-target` of a mailbox request.
    fn target(&self) -> Option<&str> {
        self.path.strip_prefix(PREFIX)
    }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn postcard(status: u16, body: Vec<u8>) -> Resp {
        Resp {
            status,
            headers: vec![(
                "content-type".into(),
                onepass_mailbox_proto::CONTENT_TYPE.into(),
            )],
            body,
        }
    }

    fn empty(status: u16) -> Resp {
        Resp {
            status,
            headers: vec![],
            body: vec![],
        }
    }

    fn error(code: ErrorCode, status: u16, retry_after: Option<u32>) -> Resp {
        Resp::postcard(status, encode(&ErrorBody { code, retry_after }))
    }
}

type Handler = dyn Fn(&Req, &str) -> Resp + Send + Sync;

struct Server {
    origin: String,
    reqs: Arc<Mutex<Vec<Req>>>,
}

impl Server {
    fn start(handler: impl Fn(&Req, &str) -> Resp + Send + Sync + 'static) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let reqs = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let (o, r) = (origin.clone(), reqs.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (o, r, h) = (o.clone(), r.clone(), handler.clone());
                std::thread::spawn(move || serve_one(stream, &o, &r, &*h));
            }
        });
        Server { origin, reqs }
    }

    fn base(&self) -> String {
        format!("{}{PREFIX}", self.origin)
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint {
            base_url: self.base(),
            extra_ca_pem: None,
        }
    }

    fn requests(&self) -> Vec<Req> {
        self.reqs.lock().unwrap().clone()
    }
}

fn serve_one(stream: TcpStream, origin: &str, reqs: &Mutex<Vec<Req>>, h: &Handler) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
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
        reader.read_line(&mut l).unwrap();
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
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).unwrap();
    let req = Req {
        method,
        path,
        headers,
        body,
    };
    reqs.lock().unwrap().push(req.clone());
    let resp = h(&req, origin);
    let mut out = format!(
        "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n",
        resp.status,
        resp.body.len()
    );
    for (n, v) in &resp.headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut stream = stream;
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(&resp.body);
}

/// Checks a signed request like the edge function (spec 4.7) and returns
/// the key id it was signed with.
fn verify(req: &Req, keys: &HashMap<[u8; 16], [u8; 32]>) -> Result<[u8; 16], String> {
    let target = req.target().ok_or("not a mailbox request")?;
    let parsed = parse_signature_headers(
        req.header("signature-input").ok_or("no signature-input")?,
        req.header("signature").ok_or("no signature")?,
    )
    .map_err(|e| e.to_string())?;
    let digest = req.header("content-digest").ok_or("no content-digest")?;
    if digest != content_digest(&req.body) {
        return Err("digest".into());
    }
    let base =
        signature_base(&req.method, target, digest, &parsed.params).map_err(|e| e.to_string())?;
    let key = keys.get(&parsed.params.keyid).ok_or("unknown key id")?;
    if credential_id(key) != parsed.params.keyid {
        return Err("key id".into());
    }
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&base, &parsed.sig)
        .map_err(|_| "signature".to_string())?;
    Ok(parsed.params.keyid)
}

fn info_body() -> MailboxInfo {
    MailboxInfo {
        incarnation: 5,
        wake_topic: [3; 16],
        min_cursor: 0,
        limits: Limits {
            max_bytes: 1 << 28,
            max_records: 100_000,
            max_credentials: 16,
            req_per_min: 120,
            max_commit_ops: 20_000,
        },
        usage: Usage {
            bytes: 0,
            records: 0,
            credentials: 1,
        },
    }
}

fn record(seq: u64, kind: u8, id: [u8; 16], body: Option<Body>) -> ServerRecord {
    ServerRecord {
        seq,
        kind,
        id,
        version: 1,
        body,
    }
}

/// A well behaved mailbox and Storage: every route answers as the edge
/// function would. `blobs` holds what was uploaded, by hex name.
fn api(req: &Req, origin: &str, blobs: &Mutex<BTreeMap<String, Vec<u8>>>) -> Resp {
    let path = req.path.as_str();
    if let Some(name) = path.strip_prefix("/storage/up/") {
        assert_eq!(req.method, "PUT");
        blobs.lock().unwrap().insert(name.into(), req.body.clone());
        return Resp::empty(200);
    }
    if let Some(name) = path.strip_prefix("/storage/get/") {
        return match blobs.lock().unwrap().get(name) {
            Some(b) => Resp {
                status: 200,
                headers: vec![],
                body: b.clone(),
            },
            None => Resp::empty(404),
        };
    }
    let target = req.target().expect("mailbox path");
    let (route, query) = target.split_once('?').unwrap_or((target, ""));
    let m = format!("/v1/mailboxes/{}", hex(&MAILBOX));
    let ok = |b: Vec<u8>| Resp::postcard(200, b);
    match (req.method.as_str(), route) {
        ("GET", "/v1/config") => ok(encode(&ServerConfig {
            realtime_url: "wss://example.invalid/realtime/v1".into(),
            publishable_key: "pk".into(),
            open_signup: false,
        })),
        ("POST", "/v1/mailboxes") => {
            decode::<CreateMailbox>(&req.body).unwrap();
            ok(encode(&MailboxCreated {
                mailbox_id: MAILBOX,
                incarnation: 5,
                wake_topic: [3; 16],
            }))
        }
        ("GET", r) if r == m => ok(encode(&info_body())),
        ("POST", r) if r == format!("{m}/credentials") => {
            decode::<Enroll>(&req.body).unwrap();
            Resp::empty(204)
        }
        ("DELETE", r) if r.starts_with(&format!("{m}/credentials/")) => Resp::empty(204),
        ("PUT", r) if r == format!("{m}/push") => {
            decode::<SetPush>(&req.body).unwrap();
            Resp::empty(204)
        }
        ("GET", r) if r == format!("{m}/changes") => {
            let q = ChangesQuery::parse(query).unwrap();
            ok(encode(&ChangesPage {
                incarnation: 5,
                min_cursor: 0,
                head: q.after,
                records: vec![],
                next_after: q.after,
                more: false,
            }))
        }
        ("POST", r) if r == format!("{m}/commit") => {
            let c = decode::<CommitRequest>(&req.body).unwrap();
            let seqs = (1..=c.ops.len() as u64).map(Some).collect();
            ok(encode(&CommitResponse::Applied { seqs }))
        }
        ("GET", r) if r.starts_with(&format!("{m}/records/")) => ok(encode(&record(
            4,
            1,
            [1; 16],
            Some(Body::Inline(b"x".to_vec())),
        ))),
        ("POST", r) if r == format!("{m}/blobs/uploads") => {
            let a = decode::<BlobAnnounce>(&req.body).unwrap();
            let have = blobs.lock().unwrap();
            let urls = a
                .blobs
                .iter()
                .map(|(sha, _)| {
                    let name = hex(sha);
                    let url =
                        (!have.contains_key(&name)).then(|| format!("{origin}/storage/up/{name}"));
                    (*sha, url)
                })
                .collect();
            ok(encode(&BlobUrls { urls }))
        }
        ("POST", r) if r == format!("{m}/blobs/downloads") => {
            let l = decode::<BlobLookup>(&req.body).unwrap();
            let urls = l
                .blobs
                .iter()
                .map(|sha| (*sha, Some(format!("{origin}/storage/get/{}", hex(sha)))))
                .collect();
            ok(encode(&BlobUrls { urls }))
        }
        _ => Resp::error(ErrorCode::NoRoute, 404, None),
    }
}

/// Uploaded objects of the fake Storage, by hex name.
type Objects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

fn api_server() -> (Server, Objects) {
    let blobs = Arc::new(Mutex::new(BTreeMap::new()));
    let b = blobs.clone();
    (Server::start(move |r, o| api(r, o, &b)), blobs)
}

fn client(server: &Server) -> (MailboxClient, CredentialKey) {
    let cred = Credential::generate().unwrap();
    let key = cred.public_key();
    let mut c = MailboxClient::new(server.endpoint(), cred).unwrap();
    c.open(MAILBOX);
    (c, key)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn put(kind: u8, id: u8, body: Body) -> CommitOp {
    CommitOp {
        kind,
        id: [id; 16],
        version: 1,
        op: Op::Put {
            expected: None,
            body,
        },
    }
}

fn delete(kind: u8, id: u8) -> CommitOp {
    CommitOp {
        kind,
        id: [id; 16],
        version: 2,
        op: Op::Delete,
    }
}

// ------------------------------------------------------------------ tests

#[test]
fn every_request_is_signed() {
    let (server, _) = api_server();
    let first = Credential::generate().unwrap();
    let first_key = first.public_key();
    let mut a = MailboxClient::new(server.endpoint(), first).unwrap();
    assert_eq!(a.mailbox(), None);
    let created = a.create(Some(b"invite"), b"phone").unwrap();
    assert_eq!(created.mailbox_id, MAILBOX);
    assert_eq!(a.mailbox(), Some(MAILBOX));

    a.server_config().unwrap();
    a.info().unwrap();
    a.changes(0, 1000, true).unwrap();
    a.commit(vec![put(1, 1, Body::Inline(b"a".to_vec()))])
        .unwrap();
    a.record(1, [1; 16]).unwrap().unwrap();
    a.revoke([7; 16]).unwrap();
    a.set_push(PushKind::Fcm, b"token").unwrap();
    let big = vec![5u8; INLINE_MAX + 1];
    let body = a.body_for(&big).unwrap();
    a.upload_blobs(&[&big]).unwrap();
    assert_eq!(a.fetch_body(&body).unwrap(), big);

    let second = Credential::generate().unwrap();
    let second_key = second.public_key();
    let ticket = a.issue_ticket(second_key, now()).unwrap();
    let mut b = MailboxClient::new(server.endpoint(), second).unwrap();
    b.enroll(&ticket, b"laptop").unwrap();
    assert_eq!(b.mailbox(), Some(MAILBOX));

    let keys = HashMap::from([
        (first_key.id(), first_key.to_bytes()),
        (second_key.id(), second_key.to_bytes()),
    ]);
    let reqs = server.requests();
    let mut seen = HashSet::new();
    for r in &reqs {
        if r.path.starts_with("/storage/") {
            // Storage gets the signed URL only, never our signature.
            assert!(r.header("signature").is_none(), "{}", r.path);
            assert!(r.header("signature-input").is_none(), "{}", r.path);
            continue;
        }
        let target = r.target().unwrap();
        if target == "/v1/config" {
            continue;
        }
        let kid = verify(r, &keys).unwrap_or_else(|e| panic!("{} {target}: {e}", r.method));
        seen.insert((
            r.method.clone(),
            target.split('?').next().unwrap().to_string(),
        ));
        // Create and enroll are signed by the key they bring in.
        if target.ends_with("/credentials") {
            assert_eq!(kid, second_key.id());
        } else {
            assert_eq!(kid, first_key.id());
        }
        if !r.body.is_empty() {
            assert_eq!(
                r.header("content-type"),
                Some(onepass_mailbox_proto::CONTENT_TYPE)
            );
        }
    }
    let m = format!("/v1/mailboxes/{}", hex(&MAILBOX));
    for (method, route) in [
        ("POST", "/v1/mailboxes".to_string()),
        ("GET", m.clone()),
        ("GET", format!("{m}/changes")),
        ("POST", format!("{m}/commit")),
        ("GET", format!("{m}/records/1/{}", hex(&[1; 16]))),
        ("DELETE", format!("{m}/credentials/{}", hex(&[7; 16]))),
        ("PUT", format!("{m}/push")),
        ("POST", format!("{m}/blobs/uploads")),
        ("POST", format!("{m}/blobs/downloads")),
        ("POST", format!("{m}/credentials")),
    ] {
        assert!(
            seen.contains(&(method.to_string(), route.clone())),
            "{method} {route}"
        );
    }
    let changes = reqs.iter().find(|r| r.path.contains("/changes")).unwrap();
    assert_eq!(
        changes.target().unwrap(),
        format!("{m}/changes?after=0&limit=1000&full=1")
    );
}

#[test]
fn nonces_are_unique() {
    let (server, _) = api_server();
    let (c, key) = client(&server);
    for _ in 0..1000 {
        c.info().unwrap();
    }
    let keys = HashMap::from([(key.id(), key.to_bytes())]);
    let mut nonces = HashSet::new();
    for r in server.requests() {
        verify(&r, &keys).unwrap();
        let p = parse_signature_headers(
            r.header("signature-input").unwrap(),
            r.header("signature").unwrap(),
        )
        .unwrap();
        nonces.insert(p.params.nonce);
    }
    assert_eq!(nonces.len(), 1000);
}

#[test]
fn skewed_clock_maps_to_stale_request() {
    let server = Server::start(|req, _| {
        let p = parse_signature_headers(
            req.header("signature-input").unwrap(),
            req.header("signature").unwrap(),
        )
        .unwrap();
        if check_skew(p.params.created, now()).is_err() {
            return Resp::error(ErrorCode::StaleRequest, 401, None);
        }
        Resp::postcard(200, encode(&info_body()))
    });
    let (c, _) = client(&server);
    assert!(c.info().is_ok());
    let c = c.with_clock(Box::new(|| now() - 3600));
    assert_eq!(c.info().unwrap_err(), MailboxError::Stale);
}

#[test]
fn error_bodies_map() {
    let answer: Arc<Mutex<Resp>> = Arc::new(Mutex::new(Resp::empty(500)));
    let a = answer.clone();
    let server = Server::start(move |_, _| {
        let r = a.lock().unwrap();
        Resp {
            status: r.status,
            headers: r.headers.clone(),
            body: r.body.clone(),
        }
    });
    let (c, _) = client(&server);
    let cases = [
        (
            ErrorCode::Malformed,
            400,
            MailboxError::Server(ErrorCode::Malformed),
        ),
        (
            ErrorCode::BadSignature,
            401,
            MailboxError::Server(ErrorCode::BadSignature),
        ),
        (ErrorCode::StaleRequest, 401, MailboxError::Stale),
        (
            ErrorCode::Replay,
            401,
            MailboxError::Server(ErrorCode::Replay),
        ),
        (
            ErrorCode::UnknownCredential,
            403,
            MailboxError::Server(ErrorCode::UnknownCredential),
        ),
        (
            ErrorCode::RevokedCredential,
            403,
            MailboxError::Server(ErrorCode::RevokedCredential),
        ),
        (
            ErrorCode::Frozen,
            403,
            MailboxError::Server(ErrorCode::Frozen),
        ),
        (
            ErrorCode::NotFound,
            404,
            MailboxError::Server(ErrorCode::NotFound),
        ),
        (ErrorCode::CursorExpired, 410, MailboxError::CursorExpired),
        (ErrorCode::TooLarge, 413, MailboxError::TooLarge),
        (
            ErrorCode::Quota,
            422,
            MailboxError::Server(ErrorCode::Quota),
        ),
        (
            ErrorCode::RateLimited,
            429,
            MailboxError::Retry { after: None },
        ),
        (ErrorCode::Retry, 503, MailboxError::Retry { after: None }),
        (
            ErrorCode::NoRoute,
            404,
            MailboxError::Server(ErrorCode::NoRoute),
        ),
    ];
    for (code, status, want) in cases {
        *answer.lock().unwrap() = Resp::error(code, status, None);
        assert_eq!(c.info().unwrap_err(), want, "{code:?}");
    }
    // 429 with retry_after in the body (and the header the edge function adds).
    let mut r = Resp::error(ErrorCode::RateLimited, 429, Some(7));
    r.headers.push(("retry-after".into(), "7".into()));
    *answer.lock().unwrap() = r;
    assert_eq!(
        c.info().unwrap_err(),
        MailboxError::Retry { after: Some(7) }
    );
    // A bare 429 from a gateway: the Retry-After header alone.
    *answer.lock().unwrap() = Resp {
        status: 429,
        headers: vec![("retry-after".into(), "9".into())],
        body: vec![],
    };
    assert_eq!(
        c.info().unwrap_err(),
        MailboxError::Retry { after: Some(9) }
    );
    // A hint above an hour is cut to an hour.
    *answer.lock().unwrap() = Resp::error(ErrorCode::RateLimited, 429, Some(1_000_000));
    assert_eq!(
        c.info().unwrap_err(),
        MailboxError::Retry { after: Some(3600) }
    );
    // A code with another code's status is malformed (500 + cursor_expired
    // must not start a full fetch).
    *answer.lock().unwrap() = Resp::error(ErrorCode::CursorExpired, 500, None);
    assert_eq!(
        c.info().unwrap_err(),
        MailboxError::Malformed("error status")
    );
    // A gateway's bare 413 tells the batch splitter to cut.
    *answer.lock().unwrap() = Resp::empty(413);
    assert_eq!(c.info().unwrap_err(), MailboxError::TooLarge);
    // A bare 502 or 503 from a gateway is a retry too.
    *answer.lock().unwrap() = Resp::empty(502);
    assert_eq!(c.info().unwrap_err(), MailboxError::Retry { after: None });
    // An error status with garbage is malformed.
    *answer.lock().unwrap() = Resp::postcard(400, vec![1, 200, 3]);
    assert!(matches!(c.info().unwrap_err(), MailboxError::Malformed(_)));
    // A redirect is never followed.
    *answer.lock().unwrap() = Resp {
        status: 302,
        headers: vec![("location".into(), "https://example.invalid/".into())],
        body: vec![],
    };
    assert_eq!(c.info().unwrap_err(), MailboxError::Malformed("redirect"));
    // 200 with another content type is malformed.
    *answer.lock().unwrap() = Resp {
        status: 200,
        headers: vec![("content-type".into(), "text/html".into())],
        body: encode(&info_body()),
    };
    assert!(matches!(c.info().unwrap_err(), MailboxError::Malformed(_)));
}

#[test]
fn connection_refused_is_offline() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cred = Credential::generate().unwrap();
    let mut c = MailboxClient::new(
        Endpoint {
            base_url: format!("http://127.0.0.1:{port}{PREFIX}"),
            extra_ca_pem: None,
        },
        cred,
    )
    .unwrap();
    c.open(MAILBOX);
    assert_eq!(c.info().unwrap_err(), MailboxError::Offline);
    assert_eq!(c.server_config().unwrap_err(), MailboxError::Offline);
}

#[test]
fn inline_blob_threshold() {
    let (server, _) = api_server();
    let (c, _) = client(&server);
    assert!(matches!(
        c.body_for(&vec![1; INLINE_MAX]).unwrap(),
        Body::Inline(d) if d.len() == 16_384
    ));
    let at = |n: usize| c.body_for(&vec![1; n]);
    assert!(matches!(
        at(16_385).unwrap(),
        Body::Blob { size: 16_385, .. }
    ));
    let data = vec![1; 921_600];
    assert_eq!(
        c.body_for(&data).unwrap(),
        Body::Blob {
            sha256: blob_sha256(&data),
            size: 921_600
        }
    );
    assert_eq!(RECORD_MAX, 921_600);
    assert_eq!(at(921_601).unwrap_err(), MailboxError::TooLarge);
}

#[test]
fn fetch_body_checks_hash() {
    let (server, blobs) = api_server();
    let (c, _) = client(&server);
    let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    let body = c.body_for(&data).unwrap();
    c.upload_blobs(&[&data]).unwrap();
    assert_eq!(c.fetch_body(&body).unwrap(), data);
    // One byte changed in Storage.
    blobs.lock().unwrap().values_mut().for_each(|b| b[100] ^= 1);
    assert_eq!(
        c.fetch_body(&body).unwrap_err(),
        MailboxError::Integrity("blob")
    );
    // Truncated, or longer than announced.
    blobs.lock().unwrap().values_mut().for_each(|b| {
        b[100] ^= 1;
        b.pop();
    });
    assert_eq!(
        c.fetch_body(&body).unwrap_err(),
        MailboxError::Integrity("blob")
    );
    blobs.lock().unwrap().values_mut().for_each(|b| {
        b.push(0);
        b.push(0);
    });
    assert_eq!(
        c.fetch_body(&body).unwrap_err(),
        MailboxError::Integrity("blob")
    );
    // Inline bodies come back as they are.
    assert_eq!(
        c.fetch_body(&Body::Inline(b"abc".to_vec())).unwrap(),
        b"abc"
    );
}

#[test]
fn tls_only_13() {
    let config = tls_client_config(&Endpoint {
        base_url: "https://example.invalid/functions/v1/mailbox".into(),
        extra_ca_pem: None,
    })
    .unwrap();
    let provider = config.crypto_provider();
    assert!(!provider.cipher_suites.is_empty());
    for suite in &provider.cipher_suites {
        assert_eq!(
            suite.version().version,
            rustls::ProtocolVersion::TLSv1_3,
            "{suite:?}"
        );
    }
    assert_eq!(
        provider.kx_groups[0].name(),
        rustls::NamedGroup::X25519MLKEM768
    );
    // A self-host CA that is not PEM is refused.
    assert!(matches!(
        tls_client_config(&Endpoint {
            base_url: "https://example.invalid".into(),
            extra_ca_pem: Some("not a certificate".into()),
        }),
        Err(MailboxError::Tls(_))
    ));
}

#[test]
fn https_required() {
    let new = |url: &str| {
        MailboxClient::new(
            Endpoint {
                base_url: url.into(),
                extra_ca_pem: None,
            },
            Credential::generate().unwrap(),
        )
    };
    for bad in [
        "http://example.com",
        "http://example.com/functions/v1/mailbox",
        "ftp://example.com",
        "example.com",
        "https://",
        "https:///x",
        "https://user@example.com",
        "https://example.com/a?b",
        "https://example.com/a#b",
        "https://exa mple.com",
        "http://127.0.0.1.example.com",
    ] {
        assert!(new(bad).is_err(), "{bad}");
    }
    let long = format!("https://example.com/{}", "a".repeat(300));
    assert!(new(&long).is_err());
    assert!(new("https://example.com/functions/v1/mailbox").is_ok());
    assert!(new("https://example.com/functions/v1/mailbox/").is_ok());
    // Loopback in plain http only in test builds (feature testing).
    assert!(new("http://127.0.0.1:54321/functions/v1/mailbox").is_ok());
    assert!(new("http://localhost:54321/functions/v1/mailbox").is_ok());
}

#[test]
fn credential_debug_hides_seed() {
    let seed = [0x42u8; 32];
    let c = Credential::from_seed(&seed).unwrap();
    let shown = format!("{c:?}");
    assert!(!shown.contains(&hex(&seed)), "{shown}");
    assert!(!shown.contains("66, 66"), "{shown}");
    assert!(shown.contains(&hex(&c.id())), "{shown}");
    assert_eq!(&c.seed()[..], &seed);
    assert_eq!(c.id(), credential_id(&c.public_key().to_bytes()));
    assert_eq!(c.public_key().id(), c.id());
    assert!(Credential::from_seed(&[1; 31]).is_err());
    // Deterministic from the seed, and the signature verifies.
    let again = Credential::from_seed(&seed).unwrap();
    assert_eq!(again.public_key(), c.public_key());
    let sig = c.sign(b"msg");
    UnparsedPublicKey::new(&ED25519, c.public_key().to_bytes())
        .verify(b"msg", &sig)
        .unwrap();
}

// --------------------------------------------- carried from Tasks 1 to 8

#[test]
fn issue_ticket_signs_a_five_minute_ticket() {
    let (server, _) = api_server();
    let cred = Credential::generate().unwrap();
    let key = cred.public_key();
    let mut c = MailboxClient::new(server.endpoint(), cred).unwrap();
    assert!(c.issue_ticket(key, now()).is_err(), "no mailbox open");
    c.open(MAILBOX);
    let newcomer = Credential::generate().unwrap().public_key();
    let t1 = c.issue_ticket(newcomer, 1_800_000_000).unwrap();
    let t2 = c.issue_ticket(newcomer, 1_800_000_000).unwrap();
    assert_ne!(t1.ticket.nonce, t2.ticket.nonce);
    assert_eq!(t1.ticket.expires_at, 1_800_000_300);
    assert_eq!(t1.ticket.mailbox_url, server.base());
    assert_eq!(t1.ticket.mailbox_id, MAILBOX);
    assert_eq!(t1.ticket.new_credential_pub, newcomer.to_bytes());
    assert_eq!(t1.approver_credential, key.id());
    UnparsedPublicKey::new(&ED25519, key.to_bytes())
        .verify(&ticket_signed_bytes(&t1.ticket), &t1.sig)
        .unwrap();
}

#[test]
fn enroll_checks_the_ticket_is_for_this_key_and_server() {
    let (server, _) = api_server();
    let (a, _) = client(&server);
    let other = Credential::generate().unwrap().public_key();
    let ticket = a.issue_ticket(other, now()).unwrap();
    let mut b = MailboxClient::new(server.endpoint(), Credential::generate().unwrap()).unwrap();
    assert!(matches!(
        b.enroll(&ticket, b"x").unwrap_err(),
        MailboxError::Malformed(_)
    ));
    let cred = Credential::generate().unwrap();
    let mut ticket = a.issue_ticket(cred.public_key(), now()).unwrap();
    ticket.ticket.mailbox_url = "https://elsewhere.invalid/functions/v1/mailbox".into();
    let mut b = MailboxClient::new(server.endpoint(), cred).unwrap();
    assert!(matches!(
        b.enroll(&ticket, b"x").unwrap_err(),
        MailboxError::Malformed(_)
    ));
    assert_eq!(b.mailbox(), None);
    // No request reached the server for either refusal.
    assert!(
        server
            .requests()
            .iter()
            .all(|r| !r.path.ends_with("/credentials"))
    );
}

#[test]
fn create_without_invite_refused_is_a_clear_error() {
    let server = Server::start(|req, _| match req.target() {
        Some("/v1/config") => Resp::postcard(
            200,
            encode(&ServerConfig {
                realtime_url: "wss://x.invalid".into(),
                publishable_key: "pk".into(),
                open_signup: true,
            }),
        ),
        _ => Resp::error(ErrorCode::Malformed, 400, None),
    });
    let mut c = MailboxClient::new(server.endpoint(), Credential::generate().unwrap()).unwrap();
    assert!(c.server_config().unwrap().open_signup);
    assert_eq!(
        c.create(None, b"x").unwrap_err(),
        MailboxError::InviteRequired
    );
    // With an invite, a malformed answer stays malformed.
    assert_eq!(
        c.create(Some(b"inv"), b"x").unwrap_err(),
        MailboxError::Server(ErrorCode::Malformed)
    );
    assert_eq!(c.mailbox(), None);
}

#[test]
fn commit_body_is_checked_before_sending() {
    let (server, _) = api_server();
    let (c, _) = client(&server);
    assert!(matches!(
        c.commit(vec![]).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    // 300 inline puts of 16 KiB: about 4.9 MiB, above COMMIT_BODY_MAX.
    let ops: Vec<CommitOp> = (0..300u16)
        .map(|i| CommitOp {
            kind: 1,
            id: {
                let mut id = [0; 16];
                id[..2].copy_from_slice(&i.to_be_bytes());
                id
            },
            version: 1,
            op: Op::Put {
                expected: None,
                body: Body::Inline(vec![0; INLINE_MAX]),
            },
        })
        .collect();
    assert!(encode(&CommitRequest { ops: ops.clone() }).len() > COMMIT_BODY_MAX);
    assert_eq!(c.commit(ops).unwrap_err(), MailboxError::TooLarge);
    // Duplicate keys are refused locally too.
    assert!(matches!(
        c.commit(vec![delete(1, 1), delete(1, 1)]).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    assert!(
        server
            .requests()
            .iter()
            .all(|r| !r.path.ends_with("/commit"))
    );
}

#[test]
fn commit_answers_are_checked() {
    let answer: Arc<Mutex<CommitResponse>> =
        Arc::new(Mutex::new(CommitResponse::Applied { seqs: vec![] }));
    let a = answer.clone();
    let server = Server::start(move |_, _| {
        let r = a.lock().unwrap().clone();
        let status = if matches!(r, CommitResponse::Conflict { .. }) {
            409
        } else {
            200
        };
        Resp::postcard(status, encode(&r))
    });
    let (c, _) = client(&server);
    let ops = || {
        vec![
            put(1, 1, Body::Inline(b"a".to_vec())),
            delete(1, 2),
            put(1, 3, Body::Inline(b"c".to_vec())),
        ]
    };
    let set = |r: CommitResponse| *answer.lock().unwrap() = r;

    // A delete that changed nothing has no seq.
    set(CommitResponse::Applied {
        seqs: vec![Some(10), None, Some(11)],
    });
    assert_eq!(
        c.commit(ops()).unwrap(),
        CommitResponse::Applied {
            seqs: vec![Some(10), None, Some(11)]
        }
    );
    for bad in [
        vec![Some(10), None],               // one seq short
        vec![None, None, Some(11)],         // a put without seq
        vec![Some(11), None, Some(10)],     // seqs going down
        vec![Some(10), Some(10), Some(11)], // a seq twice
    ] {
        set(CommitResponse::Applied { seqs: bad.clone() });
        assert!(
            matches!(c.commit(ops()).unwrap_err(), MailboxError::Malformed(_)),
            "{bad:?}"
        );
    }

    // A capped conflict list: a prefix of the conflicting keys in batch
    // order, handed back as it is (the caller resubmits to see the rest).
    let entry = |id: u8, server| ConflictEntry {
        kind: 1,
        id: [id; 16],
        server,
    };
    let current = vec![
        entry(
            1,
            Some(record(4, 1, [1; 16], Some(Body::Inline(b"s".to_vec())))),
        ),
        entry(3, None),
    ];
    set(CommitResponse::Conflict {
        current: current.clone(),
    });
    assert_eq!(
        c.commit(ops()).unwrap(),
        CommitResponse::Conflict { current }
    );
    for bad in [
        vec![],                                            // empty
        vec![entry(3, None), entry(1, None)],              // out of order
        vec![entry(4, None)],                              // not in the batch
        vec![entry(1, Some(record(4, 1, [2; 16], None)))], // other key
        vec![entry(1, None), entry(1, None)],              // twice
    ] {
        set(CommitResponse::Conflict {
            current: bad.clone(),
        });
        assert!(
            matches!(c.commit(ops()).unwrap_err(), MailboxError::Malformed(_)),
            "{bad:?}"
        );
    }
}

#[test]
fn blob_announces_go_by_one_thousand() {
    let (server, blobs) = api_server();
    let (c, _) = client(&server);
    let data: Vec<Vec<u8>> = (0..1001u32)
        .map(|i| {
            let mut d = vec![0u8; INLINE_MAX + 1];
            d[..4].copy_from_slice(&i.to_be_bytes());
            d
        })
        .collect();
    let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    c.upload_blobs(&refs).unwrap();
    let announces: Vec<BlobAnnounce> = server
        .requests()
        .iter()
        .filter(|r| r.path.ends_with("/blobs/uploads"))
        .map(|r| decode(&r.body).unwrap())
        .collect();
    assert_eq!(
        announces.iter().map(|a| a.blobs.len()).collect::<Vec<_>>(),
        [1000, 1]
    );
    assert_eq!(blobs.lock().unwrap().len(), 1001);
    // Already present: announced, not uploaded again.
    let before = server.requests().len();
    c.upload_blobs(&refs[..3]).unwrap();
    let after = server.requests();
    assert_eq!(after.len(), before + 1);
    // A body that belongs inline is not a blob.
    assert!(c.upload_blobs(&[&[1u8; 10]]).is_err());
}

#[test]
fn blob_urls_must_answer_what_was_asked() {
    let server = Server::start(|req, origin| {
        if req.path.ends_with("/blobs/uploads") {
            // Answers for another hash.
            let url = format!("{origin}/storage/up/x");
            return Resp::postcard(
                200,
                encode(&BlobUrls {
                    urls: vec![([0; 32], Some(url))],
                }),
            );
        }
        if req.path.ends_with("/blobs/downloads") {
            return Resp::postcard(
                200,
                encode(&BlobUrls {
                    urls: vec![([0; 32], Some(format!("{origin}/storage/get/x")))],
                }),
            );
        }
        Resp::empty(500)
    });
    let (c, _) = client(&server);
    let data = vec![1u8; INLINE_MAX + 1];
    assert!(matches!(
        c.upload_blobs(&[&data]).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    let body = c.body_for(&data).unwrap();
    assert!(matches!(
        c.fetch_body(&body).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    assert!(
        server
            .requests()
            .iter()
            .all(|r| !r.path.starts_with("/storage/"))
    );
}

#[test]
fn collected_blob_is_announced_and_uploaded_again() {
    // The first commit naming the blob is answered malformed, as when the
    // collector took the blob between announce and commit (spec 4.11).
    let blobs = Arc::new(Mutex::new(BTreeMap::new()));
    let commits = Arc::new(Mutex::new(0));
    let (b, n) = (blobs.clone(), commits.clone());
    let server = Server::start(move |req, origin| {
        if req.path.ends_with("/commit") {
            let mut n = n.lock().unwrap();
            *n += 1;
            if *n == 1 {
                b.lock().unwrap().clear();
                return Resp::error(ErrorCode::Malformed, 400, None);
            }
        }
        api(req, origin, &b)
    });
    let (c, _) = client(&server);
    let data = vec![3u8; INLINE_MAX + 10];
    let body = c.body_for(&data).unwrap();
    let ops = vec![put(1, 1, body.clone())];
    let r = c.commit_with_blobs(ops.clone(), &[&data]).unwrap();
    assert!(matches!(r, CommitResponse::Applied { .. }));
    assert_eq!(*commits.lock().unwrap(), 2);
    let uploads = server
        .requests()
        .iter()
        .filter(|r| r.path.starts_with("/storage/up/"))
        .count();
    assert_eq!(uploads, 2);
    assert_eq!(c.fetch_body(&body).unwrap(), data);

    // Every blob a batch names must be given.
    assert!(matches!(
        c.commit_with_blobs(ops, &[]).unwrap_err(),
        MailboxError::Malformed(_)
    ));
}

#[test]
fn record_absent_is_none_but_unknown_route_is_an_error() {
    let server = Server::start(|req, _| {
        if req.path.contains("/records/1/") {
            return Resp::error(ErrorCode::NotFound, 404, None);
        }
        Resp::error(ErrorCode::NoRoute, 404, None)
    });
    let (c, _) = client(&server);
    assert_eq!(c.record(1, [1; 16]).unwrap(), None);
    assert_eq!(
        c.record(2, [1; 16]).unwrap_err(),
        MailboxError::Server(ErrorCode::NoRoute)
    );
    // A gateway 404 that is not ours is not "absent" either.
    let gateway = Server::start(|_, _| Resp::empty(404));
    let (c, _) = client(&gateway);
    assert!(matches!(
        c.record(1, [1; 16]).unwrap_err(),
        MailboxError::Malformed(_)
    ));
}

#[test]
fn record_not_found_is_none() {
    let server = Server::start(|req, _| {
        if req.path.contains("/records/1/") {
            return Resp::error(ErrorCode::NotFound, 404, None);
        }
        // Answers for another key.
        Resp::postcard(200, encode(&record(4, 2, [8; 16], None)))
    });
    let (c, _) = client(&server);
    assert_eq!(c.record(1, [1; 16]).unwrap(), None);
    assert!(matches!(
        c.record(2, [1; 16]).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    assert!(c.record(0, [1; 16]).is_err());
}

#[test]
fn full_fetch_goes_on_incrementally_from_the_first_head() {
    // Mailbox: live rows at seqs 2, 4, 6; head 6 on the first page, then a
    // commit moves the head to 9 while the fetch goes on.
    let server = Server::start(|req, _| {
        let target = req.target().unwrap();
        let q = ChangesQuery::parse(target.split_once('?').unwrap().1).unwrap();
        let live = |seq| record(seq, 1, [seq as u8; 16], Some(Body::Inline(vec![1])));
        let page = |head, records: Vec<ServerRecord>, more| {
            let next_after = records.last().map_or(q.after, |r| r.seq);
            ChangesPage {
                incarnation: 5,
                min_cursor: 0,
                head,
                records,
                next_after,
                more,
            }
        };
        let p = match (q.full, q.after) {
            (true, 0) => page(6, vec![live(2), live(4)], true),
            (true, 4) => page(9, vec![live(6), live(8)], false),
            (false, 6) => page(9, vec![live(8), record(9, 1, [2; 16], None)], false),
            (false, 9) => page(9, vec![], false),
            other => panic!("unexpected {other:?}"),
        };
        Resp::postcard(200, encode(&p))
    });
    let (c, _) = client(&server);
    let mut feed = ChangeFeed::full();
    let mut seqs = Vec::new();
    let mut pages = 0;
    loop {
        let page = c.next_changes(&mut feed, 2).unwrap();
        pages += 1;
        seqs.extend(page.records.iter().map(|r| r.seq));
        if !page.more {
            break;
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(seqs, [2, 4, 6, 8, 8, 9]);
    assert_eq!(feed, ChangeFeed::incremental(9, 5));
    let page = c.next_changes(&mut feed, 2).unwrap();
    assert!(page.records.is_empty() && !page.more);
    assert_eq!(feed, ChangeFeed::incremental(9, 5));
}

#[test]
fn change_pages_are_checked() {
    let answer: Arc<Mutex<ChangesPage>> = Arc::new(Mutex::new(ChangesPage {
        incarnation: 5,
        min_cursor: 0,
        head: 0,
        records: vec![],
        next_after: 0,
        more: false,
    }));
    let a = answer.clone();
    let server = Server::start(move |req, _| {
        if req.path.contains("/changes") {
            return Resp::postcard(200, encode(&*a.lock().unwrap()));
        }
        Resp::error(ErrorCode::CursorExpired, 410, None)
    });
    let (c, _) = client(&server);
    let set = |p: ChangesPage| *answer.lock().unwrap() = p;
    let live = |seq| record(seq, 1, [1; 16], Some(Body::Inline(vec![1])));
    let base = ChangesPage {
        incarnation: 5,
        min_cursor: 0,
        head: 20,
        records: vec![],
        next_after: 10,
        more: false,
    };
    // An empty page must echo `after`, and cannot say there is more.
    for bad in [
        ChangesPage {
            next_after: 11,
            ..base.clone()
        },
        ChangesPage {
            more: true,
            ..base.clone()
        },
        // A record at or below `after`.
        ChangesPage {
            records: vec![live(10)],
            next_after: 10,
            ..base.clone()
        },
    ] {
        set(bad.clone());
        let mut feed = ChangeFeed::incremental(10, 5);
        assert!(
            matches!(
                c.next_changes(&mut feed, 10).unwrap_err(),
                MailboxError::Malformed(_)
            ),
            "{bad:?}"
        );
        assert_eq!(feed, ChangeFeed::incremental(10, 5));
    }
    // A full fetch carries live rows only.
    set(ChangesPage {
        records: vec![record(12, 1, [1; 16], None)],
        next_after: 12,
        ..base.clone()
    });
    assert!(c.changes(10, 10, false).is_ok());
    assert!(matches!(
        c.changes(10, 10, true).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    // More records than asked for.
    set(ChangesPage {
        records: vec![live(11), live(12)],
        next_after: 12,
        ..base.clone()
    });
    assert!(matches!(
        c.changes(10, 1, false).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    set(ChangesPage {
        records: vec![live(12)],
        next_after: 12,
        more: true,
        ..base.clone()
    });
    let mut feed = ChangeFeed::incremental(10, 5);
    c.next_changes(&mut feed, 10).unwrap();
    assert_eq!(feed, ChangeFeed::incremental(12, 5));
    // In a full fetch, a later page's head below the first one is a lie.
    set(ChangesPage {
        head: 20,
        records: vec![live(12)],
        next_after: 12,
        more: true,
        ..base.clone()
    });
    let mut feed = ChangeFeed::full();
    c.next_changes(&mut feed, 10).unwrap();
    set(ChangesPage {
        head: 19,
        records: vec![live(13)],
        next_after: 13,
        more: false,
        ..base.clone()
    });
    assert!(matches!(
        c.next_changes(&mut feed, 10).unwrap_err(),
        MailboxError::Malformed(_)
    ));
    // limit is 1..=1000.
    assert!(c.changes(0, 0, false).is_err());
    assert!(c.changes(0, 1001, false).is_err());
}

#[test]
fn feed_refuses_another_incarnation() {
    let answer: Arc<Mutex<ChangesPage>> = Arc::new(Mutex::new(ChangesPage {
        incarnation: 5,
        min_cursor: 0,
        head: 20,
        records: vec![record(12, 1, [1; 16], Some(Body::Inline(vec![1])))],
        next_after: 12,
        more: true,
    }));
    let a = answer.clone();
    let server = Server::start(move |_, _| Resp::postcard(200, encode(&*a.lock().unwrap())));
    let (c, _) = client(&server);
    let changed = |r: Result<_, MailboxError>, expected, found| {
        assert_eq!(
            r.unwrap_err(),
            MailboxError::IncarnationChanged { expected, found }
        );
    };

    // Against the stored one: incremental, and a full fetch after a
    // CursorExpired.
    let mut feed = ChangeFeed::incremental(10, 4);
    changed(c.next_changes(&mut feed, 10), 4, 5);
    assert_eq!(
        feed,
        ChangeFeed::incremental(10, 4),
        "the feed did not move"
    );
    let mut feed = ChangeFeed::full_for(4);
    changed(c.next_changes(&mut feed, 10), 4, 5);
    assert_eq!(feed, ChangeFeed::full_for(4));

    // Between pages of a full fetch.
    let mut feed = ChangeFeed::full();
    assert_eq!(feed.incarnation(), None);
    c.next_changes(&mut feed, 10).unwrap();
    assert_eq!(feed.incarnation(), Some(5));
    {
        let mut p = answer.lock().unwrap();
        p.records = vec![record(13, 1, [1; 16], Some(Body::Inline(vec![1])))];
        p.next_after = 13;
        p.incarnation = 6;
    }
    let before = feed;
    changed(c.next_changes(&mut feed, 10), 5, 6);
    assert_eq!(feed, before);

    // The incarnation of a finished full fetch carries on incrementally.
    {
        let mut p = answer.lock().unwrap();
        p.records = vec![record(12, 1, [1; 16], Some(Body::Inline(vec![1])))];
        p.next_after = 12;
        p.incarnation = 5;
        p.more = false;
    }
    let mut feed = ChangeFeed::full();
    c.next_changes(&mut feed, 10).unwrap();
    assert_eq!(feed, ChangeFeed::incremental(20, 5));
    {
        let mut p = answer.lock().unwrap();
        p.incarnation = 7;
        p.records = vec![record(21, 1, [1; 16], Some(Body::Inline(vec![1])))];
        p.next_after = 21;
        p.head = 21;
    }
    changed(c.next_changes(&mut feed, 10), 5, 7);
    assert_eq!(feed, ChangeFeed::incremental(20, 5));
}

#[test]
fn self_host_ca_is_added_to_the_web_roots() {
    // A real certificate, PEM armored (ISRG Root X1 from the web roots).
    let der = webpki_root_der();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        data_encoding::BASE64.encode(&der)
    );
    assert!(
        tls_client_config(&Endpoint {
            base_url: "https://mailbox.example".into(),
            extra_ca_pem: Some(pem.clone()),
        })
        .is_ok()
    );
    assert!(
        MailboxClient::new(
            Endpoint {
                base_url: "https://mailbox.example".into(),
                extra_ca_pem: Some(pem),
            },
            Credential::generate().unwrap(),
        )
        .is_ok()
    );
}

fn webpki_root_der() -> Vec<u8> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS[0].to_vec()
}

// ------------------------------------------------------------- TLS (I1)

const CA_PEM: &str = include_str!("fixtures/ca.pem");
const LEAF_PEM: &str = include_str!("fixtures/leaf.pem");
const LEAF_KEY: &str = include_str!("fixtures/leaf.key");

/// What a TLS server saw of the handshake.
#[derive(Debug, Default, Clone)]
struct Negotiated {
    version: Option<rustls::ProtocolVersion>,
    group: Option<rustls::NamedGroup>,
}

/// A loopback TLS server (leaf for localhost, signed by the test CA) that
/// answers every request with a `ServerConfig`. `tls12_only` serves
/// TLS 1.2 alone.
fn tls_server(tls12_only: bool) -> (u16, Arc<Mutex<Negotiated>>) {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(LEAF_PEM.as_bytes())
        .chain(CertificateDer::pem_slice_iter(CA_PEM.as_bytes()))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY.as_bytes()).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only {
        provider
            .cipher_suites
            .retain(|s| s.version().version == rustls::ProtocolVersion::TLSv1_2);
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Negotiated::default()));
    let s = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (config, s) = (config.clone(), s.clone());
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                *s.lock().unwrap() = Negotiated {
                    version: tls.conn.protocol_version(),
                    group: tls.conn.negotiated_key_exchange_group().map(|g| g.name()),
                };
                let body = encode(&ServerConfig {
                    realtime_url: "wss://x.invalid".into(),
                    publishable_key: "pk".into(),
                    open_signup: false,
                });
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    onepass_mailbox_proto::CONTENT_TYPE,
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes());
                let _ = tls.write_all(&body);
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    (port, seen)
}

fn tls_client(port: u16, ca: Option<&str>) -> MailboxClient {
    MailboxClient::new(
        Endpoint {
            base_url: format!("https://localhost:{port}{PREFIX}"),
            extra_ca_pem: ca.map(str::to_string),
        },
        Credential::generate().unwrap(),
    )
    .unwrap()
}

#[test]
fn tls_handshake_with_the_self_host_ca_is_tls13_hybrid() {
    let (port, seen) = tls_server(false);
    let c = tls_client(port, Some(CA_PEM));
    assert!(!c.server_config().unwrap().open_signup);
    let n = seen.lock().unwrap().clone();
    assert_eq!(n.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(n.group, Some(rustls::NamedGroup::X25519MLKEM768));
}

#[test]
fn untrusted_certificate_is_tls_not_offline() {
    let (port, _) = tls_server(false);
    let c = tls_client(port, None);
    let err = c.server_config().unwrap_err();
    assert!(
        matches!(&err, MailboxError::Tls(w) if w.contains("certificate")),
        "{err:?}"
    );
}

#[test]
fn tls12_only_server_is_tls_not_offline() {
    let (port, _) = tls_server(true);
    let c = tls_client(port, Some(CA_PEM));
    let err = c.server_config().unwrap_err();
    assert!(matches!(err, MailboxError::Tls(_)), "{err:?}");
}

#[test]
fn garbage_instead_of_a_server_hello_is_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        }
    });
    let err = tls_client(port, None).server_config().unwrap_err();
    assert!(matches!(err, MailboxError::Tls(_)), "{err:?}");
}

// ------------------------------------------------------------ rendezvous

/// The rendezvous routes in memory: chunks written once, `wait` ignored.
fn rdv_server(bad_content_type: bool) -> Server {
    let chunks: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
    Server::start(move |req, _| {
        let target = req.target().unwrap();
        let path = target.split('?').next().unwrap().to_string();
        let mut chunks = chunks.lock().unwrap();
        match req.method.as_str() {
            "PUT" => {
                if chunks.contains_key(&path) {
                    return Resp::empty(409);
                }
                chunks.insert(path, req.body.clone());
                Resp::empty(204)
            }
            "GET" => match chunks.get(&path) {
                Some(c) => Resp {
                    status: 200,
                    headers: vec![(
                        "content-type".into(),
                        if bad_content_type {
                            onepass_mailbox_proto::CONTENT_TYPE.into()
                        } else {
                            "application/octet-stream".into()
                        },
                    )],
                    body: c.clone(),
                },
                None => Resp::empty(204),
            },
            "DELETE" => Resp::empty(204),
            _ => Resp::error(ErrorCode::NoRoute, 404, None),
        }
    })
}

#[test]
fn rendezvous_over_http() {
    let server = rdv_server(false);
    let session = [0x5a; 16];
    let mut n = Rendezvous::new(server.endpoint(), session, RdvRole::Newcomer).unwrap();
    let mut a = Rendezvous::new(server.endpoint(), session, RdvRole::Approver).unwrap();
    let frame: Vec<u8> = (0..(1 << 20) + 100).map(|i: u32| i as u8).collect();
    n.send_frame(&frame).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    assert_eq!(a.recv_frame(frame.len(), deadline).unwrap(), frame);
    // A second newcomer on the same session collides on chunk 0.
    let mut other = Rendezvous::new(server.endpoint(), session, RdvRole::Newcomer).unwrap();
    assert_eq!(
        other.send_frame(b"x").unwrap_err(),
        MailboxError::FrameTaken
    );

    let hex_s = hex(&session);
    let reqs = server.requests();
    let line = |r: &Req| format!("{} {}", r.method, r.target().unwrap());
    let lines: Vec<String> = reqs.iter().map(line).collect();
    let base = format!("/v1/rendezvous/{hex_s}");
    assert_eq!(
        lines[..5],
        [
            format!("PUT {base}/0/0"),
            format!("PUT {base}/0/1"),
            format!("GET {base}/0/0?wait=4"),
            format!("GET {base}/0/1?wait=4"),
            format!("PUT {base}/0/0"),
        ]
    );
    assert!(lines.contains(&format!("DELETE {base}")), "{lines:?}");
    let first = &reqs[0];
    assert_eq!(first.body.len(), 1 << 20);
    assert_eq!(first.body[..4], ((frame.len()) as u32).to_be_bytes());
    assert_eq!(
        first.header("content-type"),
        Some("application/octet-stream")
    );
    assert!(
        reqs.iter().all(|r| r.header("signature").is_none()),
        "nobody signs the rendezvous"
    );
}

#[test]
fn rendezvous_answers_are_checked() {
    let server = rdv_server(true);
    let session = [0x5b; 16];
    let mut n = Rendezvous::new(server.endpoint(), session, RdvRole::Newcomer).unwrap();
    n.send_frame(b"hi").unwrap();
    let mut a = Rendezvous::new(server.endpoint(), session, RdvRole::Approver).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    assert_eq!(
        a.recv_frame(8, deadline).unwrap_err(),
        MailboxError::Malformed("content type")
    );
    let deletes = server
        .requests()
        .iter()
        .filter(|r| r.method == "DELETE")
        .count();
    assert_eq!(deletes, 1, "a bad answer closes the session");
}

#[test]
fn rendezvous_reader_caps_the_stream_at_66_mib() {
    // A hostile server serves one full 1 MiB frame at every n.
    let mut chunk = (((1u32 << 20) - 4).to_be_bytes()).to_vec();
    chunk.resize(1 << 20, 7);
    let server = Server::start(move |req, _| {
        if req.method == "GET" {
            return Resp {
                status: 200,
                headers: vec![("content-type".into(), "application/octet-stream".into())],
                body: chunk.clone(),
            };
        }
        Resp::empty(204)
    });
    let mut a = Rendezvous::new(server.endpoint(), [0x5c; 16], RdvRole::Approver).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    for _ in 0..66 {
        assert_eq!(
            a.recv_frame(1 << 20, deadline).unwrap().len(),
            (1 << 20) - 4
        );
    }
    assert_eq!(
        a.recv_frame(1 << 20, deadline).unwrap_err(),
        MailboxError::Malformed("rendezvous stream size")
    );
}
