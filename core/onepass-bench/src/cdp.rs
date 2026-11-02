//! Minimal synchronous DevTools protocol client over a WebSocket (ruling R5: no async runtime,
//! no new dependency). Commands are matched to replies by id; events are queued, except
//! `Fetch.requestPaused`, which is answered at once by the [`Interceptor`] so a page never stalls
//! while the bench waits for another reply.

use std::collections::VecDeque;
use std::fmt;
use std::io::ErrorKind;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use data_encoding::BASE64;
use serde_json::{Value, json};
use tungstenite::{Message, WebSocket};

/// Header the bench adds to the document request of a live run (spec section 2).
pub const BENCH_HEADER: (&str, &str) = (
    "X-OnePass-Bench",
    "1 (+https://github.com/soma-intelligence/onepass)",
);

#[derive(Debug)]
pub enum CdpError {
    Io(String),
    Protocol(String),
    Remote(String),
    Timeout(String),
}

impl fmt::Display for CdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CdpError::Io(m) => write!(f, "io: {m}"),
            CdpError::Protocol(m) => write!(f, "protocol: {m}"),
            CdpError::Remote(m) => write!(f, "remote: {m}"),
            CdpError::Timeout(m) => write!(f, "timeout: {m}"),
        }
    }
}

impl std::error::Error for CdpError {}

pub type Result<T> = std::result::Result<T, CdpError>;

/// What happens to a paused request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let it go, adding the bench header when `announce` is set.
    Continue { announce: bool },
    /// Refuse it before it leaves the browser.
    Fail,
    /// Answer it with this HTML (offline replay).
    Fulfill(String),
}

/// Where pages come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Live,
    /// The recording of `url`; every other request is refused.
    Offline {
        url: String,
        html: String,
    },
}

fn strip_fragment(u: &str) -> &str {
    u.split('#').next().unwrap_or(u)
}

/// The interception rule (spec section 2 and 5): never anything but GET or HEAD, and offline
/// nothing but the recorded document.
pub fn decide(source: &Source, method: &str, url: &str, resource_type: &str) -> Decision {
    if method != "GET" && method != "HEAD" {
        return Decision::Fail;
    }
    match source {
        Source::Live => Decision::Continue {
            announce: resource_type == "Document",
        },
        Source::Offline { url: doc, html } => {
            if resource_type == "Document" && strip_fragment(url) == strip_fragment(doc) {
                Decision::Fulfill(html.clone())
            } else {
                Decision::Fail
            }
        }
    }
}

/// The command answering a `Fetch.requestPaused` event, or `None` when the event is malformed.
pub fn answer(source: &Source, event: &Value) -> Option<(String, Value)> {
    let p = event.get("params")?;
    let id = p.get("requestId")?.as_str()?;
    let req = p.get("request")?;
    let method = req.get("method")?.as_str()?;
    let url = req.get("url")?.as_str()?;
    let rtype = p.get("resourceType").and_then(Value::as_str).unwrap_or("");
    let cmd = match decide(source, method, url, rtype) {
        Decision::Fail => (
            "Fetch.failRequest",
            json!({"requestId": id, "errorReason": "BlockedByClient"}),
        ),
        Decision::Continue { announce: false } => {
            ("Fetch.continueRequest", json!({"requestId": id}))
        }
        Decision::Continue { announce: true } => {
            let mut headers: Vec<Value> = req
                .get("headers")
                .and_then(Value::as_object)
                .map(|h| {
                    h.iter()
                        .map(|(k, v)| json!({"name": k, "value": v.as_str().unwrap_or("")}))
                        .collect()
                })
                .unwrap_or_default();
            headers.push(json!({"name": BENCH_HEADER.0, "value": BENCH_HEADER.1}));
            (
                "Fetch.continueRequest",
                json!({"requestId": id, "headers": headers}),
            )
        }
        Decision::Fulfill(html) => (
            "Fetch.fulfillRequest",
            json!({
                "requestId": id,
                "responseCode": 200,
                "responseHeaders": [{"name": "Content-Type", "value": "text/html; charset=utf-8"}],
                "body": BASE64.encode(html.as_bytes()),
            }),
        ),
    };
    Some((cmd.0.to_string(), cmd.1))
}

/// Outcome of one inbound message.
#[derive(Debug, Clone, PartialEq)]
pub enum Inbound {
    Reply {
        id: u64,
        result: std::result::Result<Value, String>,
    },
    Event(Value),
}

pub fn classify(text: &str) -> Result<Inbound> {
    let v: Value = serde_json::from_str(text).map_err(|e| CdpError::Protocol(e.to_string()))?;
    if let Some(id) = v.get("id").and_then(Value::as_u64) {
        if let Some(err) = v.get("error") {
            let m = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("error")
                .to_string();
            return Ok(Inbound::Reply { id, result: Err(m) });
        }
        return Ok(Inbound::Reply {
            id,
            result: Ok(v.get("result").cloned().unwrap_or(Value::Null)),
        });
    }
    if v.get("method").is_some() {
        return Ok(Inbound::Event(v));
    }
    Err(CdpError::Protocol(
        "message with neither id nor method".into(),
    ))
}

pub fn command(id: u64, session: Option<&str>, method: &str, params: Value) -> String {
    let mut m = json!({"id": id, "method": method, "params": params});
    if let Some(s) = session {
        m["sessionId"] = json!(s);
    }
    m.to_string()
}

pub struct Cdp {
    ws: WebSocket<TcpStream>,
    next: u64,
    events: VecDeque<Value>,
    pub source: Source,
    /// Requests refused by the interceptor since the last [`Cdp::take_refused`].
    refused: Vec<(String, String)>,
}

impl Cdp {
    /// Connects to the browser endpoint `ws://host:port/devtools/browser/<id>`.
    pub fn connect(ws_url: &str) -> Result<Cdp> {
        let rest = ws_url
            .strip_prefix("ws://")
            .ok_or_else(|| CdpError::Protocol(format!("not a ws:// url: {ws_url}")))?;
        let addr = rest.split('/').next().unwrap_or(rest);
        let stream = TcpStream::connect(addr).map_err(|e| CdpError::Io(e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| CdpError::Io(e.to_string()))?;
        let (ws, _) = tungstenite::client::client(ws_url, stream)
            .map_err(|e| CdpError::Io(format!("handshake: {e}")))?;
        // Short reads from here on: a read that times out lets the caller check its deadline.
        ws.get_ref()
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| CdpError::Io(e.to_string()))?;
        Ok(Cdp {
            ws,
            next: 1,
            events: VecDeque::new(),
            source: Source::Live,
            refused: Vec::new(),
        })
    }

    pub fn take_refused(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.refused)
    }

    fn send_raw(&mut self, text: String) -> Result<()> {
        self.ws
            .send(Message::text(text))
            .map_err(|e| CdpError::Io(e.to_string()))
    }

    /// One inbound message, or `None` when nothing arrived before the socket timeout.
    fn read_one(&mut self) -> Result<Option<Inbound>> {
        match self.ws.read() {
            Ok(Message::Text(t)) => classify(t.as_str()).map(Some),
            Ok(Message::Close(_)) => Err(CdpError::Io("browser closed the socket".into())),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                Ok(None)
            }
            Err(e) => Err(CdpError::Io(e.to_string())),
        }
    }

    /// Handles an event: paused requests are answered at once, others are queued.
    fn on_event(&mut self, ev: Value) -> Result<()> {
        if ev.get("method").and_then(Value::as_str) == Some("Fetch.requestPaused") {
            let session = ev
                .get("sessionId")
                .and_then(Value::as_str)
                .map(str::to_string);
            if let Some((method, params)) = answer(&self.source, &ev) {
                if method == "Fetch.failRequest" {
                    let req = &ev["params"]["request"];
                    self.refused.push((
                        req["method"].as_str().unwrap_or("").to_string(),
                        req["url"].as_str().unwrap_or("").to_string(),
                    ));
                }
                let id = self.next;
                self.next += 1;
                self.send_raw(command(id, session.as_deref(), &method, params))?;
            }
            return Ok(());
        }
        self.events.push_back(ev);
        if self.events.len() > 10_000 {
            self.events.pop_front();
        }
        Ok(())
    }

    pub fn call(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value> {
        let id = self.next;
        self.next += 1;
        self.send_raw(command(id, session, method, params))?;
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() > deadline {
                return Err(CdpError::Timeout(method.to_string()));
            }
            match self.read_one()? {
                Some(Inbound::Reply { id: got, result }) if got == id => {
                    return result.map_err(CdpError::Remote);
                }
                Some(Inbound::Reply { .. }) | None => {}
                Some(Inbound::Event(ev)) => self.on_event(ev)?,
            }
        }
    }

    /// Reads and answers events for `d`.
    pub fn pump(&mut self, d: Duration) -> Result<()> {
        let deadline = Instant::now() + d;
        while Instant::now() < deadline {
            if let Some(Inbound::Event(ev)) = self.read_one()? {
                self.on_event(ev)?;
            }
        }
        Ok(())
    }

    /// Waits for an event `method` of `session`, answering others meanwhile.
    pub fn wait_event(&mut self, session: &str, method: &str, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            let pos = self.events.iter().position(|e| {
                e.get("method").and_then(Value::as_str) == Some(method)
                    && e.get("sessionId").and_then(Value::as_str) == Some(session)
            });
            if let Some(i) = pos {
                return Ok(self.events.remove(i).unwrap_or(Value::Null));
            }
            if Instant::now() > deadline {
                return Err(CdpError::Timeout(method.to_string()));
            }
            if let Some(Inbound::Event(ev)) = self.read_one()? {
                self.on_event(ev)?;
            }
        }
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paused(method: &str, url: &str, rtype: &str) -> Value {
        json!({"method": "Fetch.requestPaused", "sessionId": "S", "params": {
            "requestId": "r1", "resourceType": rtype,
            "request": {"method": method, "url": url, "headers": {"Accept": "text/html"}}}})
    }

    #[test]
    fn live_refuses_everything_but_get_and_head() {
        for m in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            assert_eq!(
                decide(&Source::Live, m, "https://a.example/x", "XHR"),
                Decision::Fail
            );
        }
        assert_eq!(
            decide(&Source::Live, "GET", "https://a.example/", "Document"),
            Decision::Continue { announce: true }
        );
        assert_eq!(
            decide(&Source::Live, "HEAD", "https://a.example/a.js", "Script"),
            Decision::Continue { announce: false }
        );
    }

    #[test]
    fn offline_serves_the_recording_only() {
        let s = Source::Offline {
            url: "https://a.example/login".into(),
            html: "<p>x</p>".into(),
        };
        assert_eq!(
            decide(&s, "GET", "https://a.example/login#top", "Document"),
            Decision::Fulfill("<p>x</p>".into())
        );
        assert_eq!(
            decide(&s, "GET", "https://a.example/app.js", "Script"),
            Decision::Fail
        );
        assert_eq!(
            decide(&s, "GET", "https://b.example/login", "Document"),
            Decision::Fail
        );
        assert_eq!(
            decide(&s, "POST", "https://a.example/login", "Document"),
            Decision::Fail
        );
    }

    #[test]
    fn answers_carry_the_request_id_and_the_header() {
        let (m, p) = answer(
            &Source::Live,
            &paused("GET", "https://a.example/", "Document"),
        )
        .unwrap();
        assert_eq!(m, "Fetch.continueRequest");
        assert_eq!(p["requestId"], "r1");
        let hs = p["headers"].as_array().unwrap();
        assert!(hs.iter().any(|h| h["name"] == BENCH_HEADER.0));
        assert!(hs.iter().any(|h| h["name"] == "Accept"));
        let (m, _) = answer(
            &Source::Live,
            &paused("POST", "https://a.example/s", "Fetch"),
        )
        .unwrap();
        assert_eq!(m, "Fetch.failRequest");
        let off = Source::Offline {
            url: "https://a.example/".into(),
            html: "hi".into(),
        };
        let (m, p) = answer(&off, &paused("GET", "https://a.example/", "Document")).unwrap();
        assert_eq!(m, "Fetch.fulfillRequest");
        assert_eq!(p["body"], BASE64.encode(b"hi"));
        assert!(answer(&Source::Live, &json!({"method": "Fetch.requestPaused"})).is_none());
    }

    #[test]
    fn framing() {
        assert_eq!(
            classify(r#"{"id":3,"result":{"a":1}}"#).unwrap(),
            Inbound::Reply {
                id: 3,
                result: Ok(json!({"a":1}))
            }
        );
        assert_eq!(
            classify(r#"{"id":4,"error":{"code":-32000,"message":"nope"}}"#).unwrap(),
            Inbound::Reply {
                id: 4,
                result: Err("nope".into())
            }
        );
        assert!(matches!(
            classify(r#"{"method":"Page.loadEventFired","params":{}}"#).unwrap(),
            Inbound::Event(_)
        ));
        assert!(classify("{}").is_err());
        assert!(classify("not json").is_err());
        let c: Value =
            serde_json::from_str(&command(7, Some("S"), "Page.enable", json!({}))).unwrap();
        assert_eq!(
            c,
            json!({"id": 7, "method": "Page.enable", "params": {}, "sessionId": "S"})
        );
        let c: Value =
            serde_json::from_str(&command(8, None, "Target.getTargets", json!({}))).unwrap();
        assert!(c.get("sessionId").is_none());
    }
}
