//! Endpoint checks, TLS configuration and the one `ureq` agent of a client.

use std::sync::Arc;
use std::time::Duration;

use onepass_mailbox_proto::{PAGE_MAX_BYTES, URL_MAX};
use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self as provider, kx_group};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use ureq::Agent;
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};

use crate::MailboxError;

/// Where a mailbox lives: the base URL that every `@onepass-target` is
/// relative to (for example `https://<project>.supabase.co/functions/v1/mailbox`),
/// and for a self-host, a CA certificate (PEM) trusted on top of the web roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub base_url: String,
    pub extra_ca_pem: Option<String>,
}

/// Whole-call deadline of every request.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Most bytes read from any mailbox answer: a full page and some slack.
pub(crate) const RESPONSE_MAX: u64 = PAGE_MAX_BYTES as u64 + 64 * 1024;

/// `https://` only. Test builds (feature `testing`) also take plain `http`
/// to `127.0.0.1` or `localhost`. Visible ASCII, no user info, no fragment;
/// a query only where `query` allows it (signed Storage URLs).
pub(crate) fn check_url(url: &str, query: bool) -> Result<(), MailboxError> {
    let bad = MailboxError::Malformed("url");
    if !url.bytes().all(|b| (0x21..=0x7e).contains(&b)) || url.contains('#') {
        return Err(bad);
    }
    if !query && url.contains('?') {
        return Err(bad);
    }
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(MailboxError::Malformed("https required"));
    };
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(bad);
    }
    if https {
        return Ok(());
    }
    if cfg!(feature = "testing") {
        let (host, port) = authority.split_once(':').unwrap_or((authority, ""));
        let port_ok = port.bytes().all(|b| b.is_ascii_digit());
        if matches!(host, "127.0.0.1" | "localhost") && port_ok {
            return Ok(());
        }
    }
    Err(MailboxError::Malformed("https required"))
}

/// The base URL without its trailing `/`, checked. It goes into enroll
/// tickets, so it holds in `URL_MAX` (256 bytes).
pub(crate) fn base_url(endpoint: &Endpoint) -> Result<String, MailboxError> {
    let base = endpoint.base_url.trim_end_matches('/');
    if base.len() > URL_MAX {
        return Err(MailboxError::Malformed("url length"));
    }
    check_url(base, false)?;
    Ok(base.to_string())
}

/// `aws-lc-rs` with TLS 1.3 suites only, so no TLS 1.2 can be offered
/// whatever features the rest of the build turns on, and the hybrid
/// `X25519MLKEM768` group offered first.
fn crypto_provider() -> Arc<CryptoProvider> {
    let mut p = provider::default_provider();
    p.cipher_suites
        .retain(|s| s.version().version == rustls::ProtocolVersion::TLSv1_3);
    p.kx_groups = vec![
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
    ];
    Arc::new(p)
}

/// The web roots, then the endpoint's own CA, every one of which must parse.
fn roots(endpoint: &Endpoint) -> Result<Vec<CertificateDer<'static>>, MailboxError> {
    let mut certs = webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec();
    if let Some(pem) = &endpoint.extra_ca_pem {
        let extra = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MailboxError::Tls(format!("extra CA: {e}")))?;
        if extra.is_empty() {
            return Err(MailboxError::Tls("extra CA: no certificate".into()));
        }
        let mut check = RootCertStore::empty();
        for c in &extra {
            check
                .add(c.clone())
                .map_err(|e| MailboxError::Tls(format!("extra CA: {e}")))?;
        }
        certs.extend(extra);
    }
    Ok(certs)
}

/// The `rustls` client configuration of an endpoint: the provider and roots
/// the client's agent uses, TLS 1.3 only.
pub fn tls_client_config(endpoint: &Endpoint) -> Result<rustls::ClientConfig, MailboxError> {
    let mut store = RootCertStore::empty();
    store.add_parsable_certificates(roots(endpoint)?);
    Ok(
        rustls::ClientConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| MailboxError::Tls(e.to_string()))?
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

pub(crate) struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    /// `Retry-After` in seconds, when it is a plain number.
    pub retry_after: Option<u32>,
    pub body: Vec<u8>,
}

pub(crate) struct Http {
    agent: Agent,
}

impl Http {
    pub(crate) fn new(endpoint: &Endpoint) -> Result<Http, MailboxError> {
        // Builds the reference configuration once: a bad CA fails here.
        tls_client_config(endpoint)?;
        let certs: Vec<Certificate<'static>> = roots(endpoint)?
            .iter()
            .map(|c| Certificate::from_der(c.as_ref()).to_owned())
            .collect();
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::new_with_certs(&certs))
            .unversioned_rustls_crypto_provider(crypto_provider())
            .build();
        let agent = Agent::config_builder()
            .tls_config(tls)
            .https_only(!cfg!(feature = "testing"))
            .timeout_global(Some(TIMEOUT))
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent("onepass-mailbox")
            .build()
            .new_agent();
        Ok(Http { agent })
    }

    /// One request. Answers of any status come back as a `Response`; a
    /// body longer than `limit` is `Malformed("response size")`.
    pub(crate) fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(&'static str, String)],
        body: &[u8],
        limit: u64,
    ) -> Result<Response, MailboxError> {
        macro_rules! with_headers {
            ($b:expr) => {{
                let mut b = $b;
                for (n, v) in headers {
                    b = b.header(*n, v.as_str());
                }
                b
            }};
        }
        let result = match method {
            Method::Get => with_headers!(self.agent.get(url)).call(),
            Method::Delete => with_headers!(self.agent.delete(url)).call(),
            Method::Post => with_headers!(self.agent.post(url)).send(body),
            Method::Put => with_headers!(self.agent.put(url)).send(body),
        };
        let mut resp = result.map_err(map_error)?;
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let content_type = header("content-type");
        let retry_after = header("retry-after").and_then(|v| {
            (!v.is_empty() && v.len() <= 9 && v.bytes().all(|b| b.is_ascii_digit()))
                .then(|| v.parse().ok())
                .flatten()
        });
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(map_error)?;
        Ok(Response {
            status,
            content_type,
            retry_after,
            body,
        })
    }
}

/// A `rustls::Error` anywhere in an error's chain: the handshake (or a
/// record) failed, as opposed to the network.
fn tls_cause(e: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(t) = err.downcast_ref::<rustls::Error>() {
            return Some(t.to_string());
        }
        cur = err.source();
    }
    None
}

fn map_error(e: ureq::Error) -> MailboxError {
    use ureq::Error as E;
    match e {
        // rustls reports handshake failures (untrusted certificate, no
        // TLS 1.3, no shared group, garbage) as an io::Error wrapping its
        // own error; ureq passes that on as Io. Not "offline": retrying
        // will not help.
        E::Io(e) => match e.get_ref().and_then(|inner| tls_cause(inner)) {
            Some(why) => MailboxError::Tls(why),
            None => MailboxError::Offline,
        },
        E::ConnectionFailed | E::HostNotFound | E::Timeout(_) => MailboxError::Offline,
        E::BodyExceedsLimit(_) => MailboxError::Malformed("response size"),
        E::Tls(w) => MailboxError::Tls(w.to_string()),
        E::Rustls(e) => MailboxError::Tls(e.to_string()),
        E::TooManyRedirects | E::RedirectFailed => MailboxError::Malformed("redirect"),
        _ => MailboxError::Malformed("http"),
    }
}
