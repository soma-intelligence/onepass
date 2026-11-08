//! The loopback check and one blocking WebSocket to a DevTools page target.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde_json::Value;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Bytes, Message, Utf8Bytes, WebSocket};
use zeroize::Zeroizing;

use crate::CdpError;

pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// A snapshot of a large page is a few MB; anything past this is refused.
const MAX_MESSAGE: usize = 64 << 20;

/// What the address check lets through: the literal loopback socket and the
/// URL rebuilt from the checked parts only.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LocalTarget {
    pub addr: SocketAddr,
    pub request: String,
}

/// Accepts `ws://127.0.0.1[:port]/path` and `ws://[::1][:port]/path` only.
/// Works on the text: no lookup, no socket. `localhost` and every other name
/// or address is [`CdpError::NotLocal`], as is any userinfo; a non-ws scheme
/// or a broken port is [`CdpError::Connect`]. `wss://` to loopback is
/// `Connect` (no TLS here), `wss://` elsewhere `NotLocal`.
pub(crate) fn check_local(url: &str) -> Result<LocalTarget, CdpError> {
    let lower = url
        .get(..6)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let (tls, rest) = if lower.starts_with("ws://") {
        (false, &url[5..])
    } else if lower.starts_with("wss://") {
        (true, &url[6..])
    } else {
        return Err(CdpError::Connect);
    };
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return Err(CdpError::NotLocal);
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.contains('@') {
        return Err(CdpError::NotLocal);
    }
    let (ip, port_part) = if let Some(v6) = authority.strip_prefix('[') {
        let close = v6.find(']').ok_or(CdpError::NotLocal)?;
        if &v6[..close] != "::1" {
            return Err(CdpError::NotLocal);
        }
        (std::net::IpAddr::V6(Ipv6Addr::LOCALHOST), &v6[close + 1..])
    } else {
        let colon = authority.find(':').unwrap_or(authority.len());
        if &authority[..colon] != "127.0.0.1" {
            return Err(CdpError::NotLocal);
        }
        (
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            &authority[colon..],
        )
    };
    if tls {
        return Err(CdpError::Connect);
    }
    let port = match port_part {
        "" => 80,
        p => {
            let digits = p.strip_prefix(':').ok_or(CdpError::NotLocal)?;
            if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(CdpError::Connect);
            }
            match digits.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => return Err(CdpError::Connect),
            }
        }
    };
    if !path.is_empty() && !path.starts_with('/') {
        return Err(CdpError::Connect);
    }
    if !path.is_ascii() {
        return Err(CdpError::Connect);
    }
    let path = if path.is_empty() { "/" } else { path };
    let host = match ip {
        std::net::IpAddr::V4(_) => "127.0.0.1".to_owned(),
        std::net::IpAddr::V6(_) => "[::1]".to_owned(),
    };
    Ok(LocalTarget {
        addr: SocketAddr::new(ip, port),
        request: format!("ws://{host}:{port}{path}"),
    })
}

fn io_error(e: &std::io::Error) -> CdpError {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => CdpError::Timeout,
        _ => CdpError::Connect,
    }
}

fn ws_error(e: tungstenite::Error) -> CdpError {
    match e {
        tungstenite::Error::Io(e) => io_error(&e),
        tungstenite::Error::Capacity(_) | tungstenite::Error::Utf8(_) => CdpError::Protocol,
        _ => CdpError::Connect,
    }
}

/// A command and its answer by id. Events and stray answers are skipped.
pub(crate) struct Socket {
    ws: WebSocket<TcpStream>,
    next_id: u64,
    command_timeout: Duration,
    /// End of the whole fill, when one is running.
    pub(crate) deadline: Option<Instant>,
    /// Set after a timeout or a broken frame: the stream may be mid-message.
    broken: bool,
}

impl Socket {
    pub(crate) fn connect(url: &str, command_timeout: Duration) -> Result<Socket, CdpError> {
        let target = check_local(url)?;
        let stream =
            TcpStream::connect_timeout(&target.addr, command_timeout).map_err(|e| io_error(&e))?;
        stream
            .set_read_timeout(Some(command_timeout))
            .and_then(|_| stream.set_write_timeout(Some(command_timeout)))
            .and_then(|_| stream.set_nodelay(true))
            .map_err(|e| io_error(&e))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let (ws, _) =
            tungstenite::client::client_with_config(target.request.as_str(), stream, Some(config))
                .map_err(|e| match e {
                    tungstenite::HandshakeError::Failure(e) => ws_error(e),
                    tungstenite::HandshakeError::Interrupted(_) => CdpError::Timeout,
                })?;
        Ok(Socket {
            ws,
            next_id: 1,
            command_timeout,
            deadline: None,
            broken: false,
        })
    }

    /// Time left for the next command: 5 s, or less when a fill is running.
    fn budget(&self) -> Result<Duration, CdpError> {
        let mut t = self.command_timeout;
        if let Some(d) = self.deadline {
            let left = d.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(CdpError::Timeout);
            }
            t = t.min(left);
        }
        Ok(t)
    }

    /// Sends `method` with `params` and waits for its result.
    pub(crate) fn call(&mut self, method: &str, params: Value) -> Result<Value, CdpError> {
        let id = self.next_id;
        self.next_id += 1;
        let text = serde_json::json!({"id": id, "method": method, "params": params}).to_string();
        self.exchange(id, Message::text(text))
    }

    /// `Input.insertText` of `value`. The command text is built in a buffer
    /// that is zeroed when the socket drops its message.
    pub(crate) fn insert_text(&mut self, value: &str) -> Result<(), CdpError> {
        let id = self.next_id;
        self.next_id += 1;
        let head = format!("{{\"id\":{id},\"method\":\"Input.insertText\",\"params\":{{\"text\":");
        // Escaping grows a byte to at most 6: one allocation, no copy left behind.
        let mut buf = Zeroizing::new(Vec::with_capacity(head.len() + value.len() * 6 + 8));
        buf.extend_from_slice(head.as_bytes());
        serde_json::to_writer(&mut *buf, value).map_err(|_| CdpError::Protocol)?;
        buf.extend_from_slice(b"}}");
        let text = Utf8Bytes::try_from(Bytes::from_owner(buf)).map_err(|_| CdpError::Protocol)?;
        self.exchange(id, Message::Text(text)).map(|_| ())
    }

    fn exchange(&mut self, id: u64, msg: Message) -> Result<Value, CdpError> {
        if self.broken {
            return Err(CdpError::Connect);
        }
        let r = self.exchange_inner(id, msg);
        if matches!(r, Err(CdpError::Timeout | CdpError::Connect)) {
            self.broken = true;
        }
        r
    }

    fn exchange_inner(&mut self, id: u64, msg: Message) -> Result<Value, CdpError> {
        let budget = self.budget()?;
        let end = Instant::now() + budget;
        self.set_timeout(budget)?;
        self.ws.send(msg).map_err(ws_error)?;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(CdpError::Timeout);
            }
            self.set_timeout(left)?;
            let text = match self.ws.read().map_err(ws_error)? {
                Message::Text(t) => t,
                Message::Close(_) => return Err(CdpError::Connect),
                _ => continue,
            };
            let v: Value = serde_json::from_str(text.as_str()).map_err(|_| CdpError::Protocol)?;
            if v.get("id").and_then(Value::as_u64) != Some(id) {
                // An event, or the late answer of an earlier command.
                continue;
            }
            if v.get("error").is_some() {
                return Err(CdpError::Protocol);
            }
            return Ok(v.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    fn set_timeout(&mut self, t: Duration) -> Result<(), CdpError> {
        let s = self.ws.get_mut();
        s.set_read_timeout(Some(t))
            .and_then(|_| s.set_write_timeout(Some(t)))
            .map_err(|e| io_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_forms() {
        let t = check_local("ws://127.0.0.1:9222/devtools/page/AB").unwrap();
        assert_eq!(t.request, "ws://127.0.0.1:9222/devtools/page/AB");
        assert_eq!(t.addr, "127.0.0.1:9222".parse().unwrap());
        let t = check_local("WS://[::1]:9222/devtools/page/AB").unwrap();
        assert_eq!(t.request, "ws://[::1]:9222/devtools/page/AB");
        let t = check_local("ws://127.0.0.1").unwrap();
        assert_eq!(t.request, "ws://127.0.0.1:80/");
    }

    #[test]
    fn refusals() {
        for u in [
            "ws://localhost:9222/",
            "ws://127.0.0.1x:9222/",
            "ws://[::2]:9222/",
            "ws://[::1:9222/",
            "ws://127.0.0.1;9222/",
            "ws://a@127.0.0.1/",
            "ws://127.0.0.1\\@evil.com/",
            "ws://127.0.0.1:9222 /",
        ] {
            assert_eq!(check_local(u), Err(CdpError::NotLocal), "{u}");
        }
        for u in [
            "http://127.0.0.1:9222/",
            "ws://127.0.0.1:/",
            "ws://127.0.0.1:0/",
            "ws://127.0.0.1:99999/",
            "ws://127.0.0.1:+80/",
            "wss://127.0.0.1:9222/",
            "ws://127.0.0.1:9222/é",
            "ws",
        ] {
            assert_eq!(check_local(u), Err(CdpError::Connect), "{u}");
        }
    }
}
